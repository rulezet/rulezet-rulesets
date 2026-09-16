rule BOUNCER_APT1_1 {
  meta:
    author  = "@abhinavbom"
    maltype = "NA"
    version = "0.1"
    date    = "21/09/2015"
    info    = "CommentCrew-threat-apt1"

  strings:
    $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
    $s2 = "IDR_DATA%d" wide ascii
    $s3 = "asdfqwe123cxz" wide ascii
    $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

  condition:
    ($s1 and $s2) or ($s3 and $s4)
}