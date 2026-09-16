rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_d88b1be24c58_5104 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1 = "(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck()" ascii
    $s2 = "(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\"" ascii
    $s3 = "(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";}" ascii
    $s4 = ",(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){r" ascii
    $s5 = "Bz\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}