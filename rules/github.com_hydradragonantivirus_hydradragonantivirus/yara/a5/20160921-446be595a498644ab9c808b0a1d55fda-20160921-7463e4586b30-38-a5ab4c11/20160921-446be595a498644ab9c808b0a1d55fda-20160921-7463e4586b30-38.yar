rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_38 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"

  strings:
    $s1  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){ret" ascii
    $s2  = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return" ascii
    $s3  = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii
    $s4  = "g\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"LGo\";})(),(function" ascii
    $s5  = "ck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx" ascii
    $s6  = "ion fuck(){return \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s7  = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck" ascii
    $s8  = "ction fuck(){return \"Ot\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s9  = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s10 = "ck(){return \"Yb\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\"" ascii
    $s11 = "ck(){return \"Xw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Xw\";" ascii
    $s12 = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s13 = "(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"SUi\";" ascii
    $s14 = "u\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Py\";})(),(function f" ascii
    $s15 = "rn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DWe\";})(),(f" ascii
    $s16 = "){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Vb\";}" ascii
    $s17 = "ion fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s18 = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return" ascii
    $s19 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Z" ascii
    $s20 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}