rule _20160921_8753c13c904d4c1e9e4a848591336ee8_20160921_d4b576a05afd_1418 {
  meta:
    description = "datamaliciousorder - from files 20160921_8753c13c904d4c1e9e4a848591336ee8.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"
    hash2       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"

  strings:
    $s1  = "ck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg" ascii
    $s2  = "tion fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s3  = " \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(funct" ascii
    $s4  = " fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"U" ascii
    $s5  = "k(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s6  = "return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s7  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s8  = "GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s9  = "\"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s10 = ",(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){" ascii
    $s11 = "(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){r" ascii
    $s12 = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retur" ascii
    $s13 = "on fuck(){return \"Bz\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"O" ascii
    $s14 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}