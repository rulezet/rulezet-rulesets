rule _20160921_ce3c0604d52e9dc9119cefedfee34385_20160921_fc08be0621d4_4060 {
  meta:
    description = "datamaliciousorder - from files 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash2       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s2 = "ck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "k(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";" ascii
    $s4 = "LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s5 = "n \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s6 = "uck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}