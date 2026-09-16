rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_7dec24f022af_3705 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"

  strings:
    $s1 = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retur" ascii
    $s2 = "n fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"" ascii
    $s3 = "turn \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(f" ascii
    $s4 = "on fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"" ascii
    $s5 = "function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){re" ascii
    $s6 = "),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}