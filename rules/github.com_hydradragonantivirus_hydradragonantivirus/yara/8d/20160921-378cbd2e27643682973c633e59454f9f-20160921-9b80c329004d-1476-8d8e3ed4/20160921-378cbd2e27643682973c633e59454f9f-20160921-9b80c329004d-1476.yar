rule _20160921_378cbd2e27643682973c633e59454f9f_20160921_9b80c329004d_1476 {
  meta:
    description = "datamaliciousorder - from files 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_9b80c329004df146d978cb7b31b22c05.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash2       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"
    hash3       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"

  strings:
    $s1  = "function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){ret" ascii
    $s2  = "return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s3  = "urn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(f" ascii
    $s4  = "(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";}" ascii
    $s5  = ";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function f" ascii
    $s6  = "fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"X" ascii
    $s7  = "v\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s8  = "k(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"SUi\"" ascii
    $s9  = "uck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Za" ascii
    $s10 = "ction fuck(){return \"FJs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s11 = "n \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s12 = "\"ILp\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\";})(),(func" ascii
    $s13 = " \"Cd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}