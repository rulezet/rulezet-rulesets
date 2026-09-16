rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_105b4651b716_486 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash3       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash4       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash5       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash6       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash7       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash8       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash9       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash10      = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash11      = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){re" ascii
    $s2  = "urn \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(f" ascii
    $s3  = "k(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"EHo\"" ascii
    $s4  = "function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){re" ascii
    $s5  = "{return \"GWo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})" ascii
    $s6  = " \"Et\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s7  = " fuck(){return \"Oh\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s8  = "urn \"ZWu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s9  = "on fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s10 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xw" ascii
    $s11 = ")(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s12 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(f" ascii
    $s13 = "n \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Et\";})(),(fun" ascii
    $s14 = "\"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s15 = "tion fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii
    $s16 = "on fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s17 = "(){return \"Xw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(" ascii
    $s18 = " fuck(){return \"ZLd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Fv" ascii
    $s19 = "\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s20 = "})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}