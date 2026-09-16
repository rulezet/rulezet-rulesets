rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_72beed3cbd32_701 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s2  = "uck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Fv\"" ascii
    $s3  = "turn \"MIl\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s4  = "\"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(fun" ascii
    $s5  = "{return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})" ascii
    $s6  = "){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})" ascii
    $s7  = "GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"RAi\";})(),(functi" ascii
    $s8  = ")(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s9  = " \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ik\";})(),(func" ascii
    $s10 = "OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OPz\";})(),(functi" ascii
    $s11 = "(){return \"GWo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";" ascii
    $s12 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii
    $s13 = "function fuck(){return \"DRx\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){re" ascii
    $s14 = "turn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})()," ascii
    $s15 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";" ascii
    $s16 = "nction fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){retur" ascii
    $s17 = "k(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq" ascii
    $s18 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s19 = "return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(" ascii
    $s20 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"X" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}