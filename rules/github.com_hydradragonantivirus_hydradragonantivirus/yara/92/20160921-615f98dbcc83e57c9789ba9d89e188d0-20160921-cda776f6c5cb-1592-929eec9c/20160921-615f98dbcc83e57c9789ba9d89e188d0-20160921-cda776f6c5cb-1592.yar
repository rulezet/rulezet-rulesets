rule _20160921_615f98dbcc83e57c9789ba9d89e188d0_20160921_cda776f6c5cb_1592 {
  meta:
    description = "datamaliciousorder - from files 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash2       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1  = "urn \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(f" ascii
    $s2  = " \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s3  = "unction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retu" ascii
    $s4  = "return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})()" ascii
    $s5  = "rn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s6  = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s7  = "),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){" ascii
    $s8  = "IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s9  = "(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";}" ascii
    $s10 = "),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(" ascii
    $s11 = "ck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\"" ascii
    $s12 = "turn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}