rule _20160921_718cbfc32cb1f435745a5a005d3f190b_20160921_940fdd83fcdf_1736 {
  meta:
    description = "datamaliciousorder - from files 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash2       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"

  strings:
    $s1  = "\"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(functi" ascii
    $s2  = "\"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";})(),(func" ascii
    $s3  = "){return \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})" ascii
    $s4  = "\"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(funct" ascii
    $s5  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(func" ascii
    $s6  = "n fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XH" ascii
    $s7  = ";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function f" ascii
    $s8  = "ck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\"" ascii
    $s9  = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s10 = "fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz" ascii
    $s11 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}