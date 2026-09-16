rule sig_20160525_c2355bcb9335c5f6da06e7d0b7c0dd8e {
  meta:
    description = "datamaliciousorder - file 20160525_c2355bcb9335c5f6da06e7d0b7c0dd8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f37a6d7c8ae6e42a0d1b1d033a9dc446e8a193a71396fc9dfd64f0aa6e1fbba5"

  strings:
    $s1 = "\\n;)eixodl + ))(};imk nruter{)(gedotdarl noitcnuf( + rerednerk + cthk(]eixodf + ))(};ime nruter{)(mf noitcnuf( + )rerednere(sui" ascii
    $s2 = "v;\"kceKHB\" = cthl rav\\n;\"s56x\\\\R\" = gsmm rav\\n;\"no07x\\\\\" = suidarelcitrapm rav\\n;\"doB56x\\\\37x\\\\\" = dnenoisill" ascii
    $s3 = "darn rav\\n;\"O44x\\\\A\" = sdnetn rav\\n;\"47x\\\\35x\\\\.BD\" = ssorcan rav\\n;\"d6x\\\\a56x\\\\r\" = tsilslianbmuhton rav\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}