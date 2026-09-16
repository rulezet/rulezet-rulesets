rule backdoor__51c46b7a {
  meta:
    description = "work1 - file backdoor_.51c46b7a.ico"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "205577f5011abfaf96d67e673023cb903ad8652b4d6f14ab8eb3fc4c232befd3"

  strings:
    $s1 = "$_cw847 = basename/*3*/(/*vts*/trim/*ic9j*/(/*9j*/preg_replace/*tb*/(/*3kqw*/rawurldecode/*ts1*/(/*sv4oc*/\"%2F%5C%28.%2A%24%2F" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (all of them)
    ) or (all of them)
}