rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_72beed3cbd32_1341 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "turn \"FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DHd\";})(),(" ascii
    $s2  = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})()" ascii
    $s3  = "return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s4  = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){ret" ascii
    $s5  = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retur" ascii
    $s6  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s7  = "on fuck(){return \"Xw\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"U" ascii
    $s8  = "(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){" ascii
    $s9  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"ZLd" ascii
    $s10 = "eturn \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s11 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return" ascii
    $s12 = ";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo\";})(),(function fu" ascii
    $s13 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return " ascii
    $s14 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s15 = "k(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}