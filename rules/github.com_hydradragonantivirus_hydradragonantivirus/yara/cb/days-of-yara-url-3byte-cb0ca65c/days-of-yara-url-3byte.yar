rule days_of_yara_url_3byte 
{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  strings:
    $target_string = /https:\/\/github\.com\/100DaysofYARA/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == 0x18074e
      and not for 0x1c4172e j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x1c4172d j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}