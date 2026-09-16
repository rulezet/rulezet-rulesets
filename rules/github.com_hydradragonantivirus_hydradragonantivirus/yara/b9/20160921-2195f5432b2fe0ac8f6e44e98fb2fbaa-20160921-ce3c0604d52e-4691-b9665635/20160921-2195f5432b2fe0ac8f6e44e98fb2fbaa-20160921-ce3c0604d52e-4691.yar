rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_ce3c0604d52e_4691 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(funct" ascii
    $s2 = " \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s3 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";" ascii
    $s5 = "(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}