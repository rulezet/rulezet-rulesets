rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_4cbbeff2b84f_4661 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"

  strings:
    $s1 = "){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MBg\";})" ascii
    $s2 = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retur" ascii
    $s3 = "n \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s4 = "tion fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}