rule sig_20151230_6f0949c785fbde9f90c8ac84b3911391 {
  meta:
    description = "datamaliciousorder - file 20151230_6f0949c785fbde9f90c8ac84b3911391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68e97b398f9a8753557dc625e1c4184f91b68b694922f4cb311bbf8ea349f64b"

  strings:
    $s1 = "print (ryszwlsd);" fullword ascii
    $s2 = "//}else{ouayjcmtl=0;" fullword ascii
    $s3 = "print (dtfrocdh);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}