rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_615f98dbcc83_4823 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash3       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s2 = "k(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(function" ascii
    $s4 = "urn \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s5 = "g\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}