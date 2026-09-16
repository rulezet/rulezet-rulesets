rule _20160921_d414cec9501c17802073a2f8f7b005c4_20160921_e6977bb87c75_5704 {
  meta:
    description = "datamaliciousorder - from files 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s2 = "rn \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(f" ascii
    $s3 = "return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})()" ascii
    $s4 = "rn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "uck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}