rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_940fdd83fcdf_3585 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash3       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "eturn \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s2 = "return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3 = "(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\"" ascii
    $s4 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PD" ascii
    $s6 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}