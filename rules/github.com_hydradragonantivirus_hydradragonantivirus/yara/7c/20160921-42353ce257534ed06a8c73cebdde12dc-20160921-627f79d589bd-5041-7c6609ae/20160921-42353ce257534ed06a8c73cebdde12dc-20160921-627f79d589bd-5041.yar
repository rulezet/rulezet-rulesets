rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_627f79d589bd_5041 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s2 = "ction fuck(){return \"DAa\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s3 = "eturn \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s4 = ",(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){r" ascii
    $s5 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}