rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_d35b8ea76f45_3702 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = "rn \"ZLd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s2 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "{return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(" ascii
    $s4 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"GWo\";})(" ascii
    $s5 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"" ascii
    $s6 = "urn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}