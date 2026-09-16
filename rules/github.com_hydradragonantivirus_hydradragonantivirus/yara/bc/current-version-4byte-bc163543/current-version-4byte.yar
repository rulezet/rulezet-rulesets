rule current_version_4byte 
{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  strings:
    $target_string = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == 0x240e1411
      and not for 0x113ecb50a j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24, i+28, i+32, i+36 ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x113ecb509 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24, i+28, i+32, i+36 ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}