rule _20160921_531eaafa1b0a00d86f2203fbd289dd63_20160921_de770f0ed114_5183 {
  meta:
    description = "datamaliciousorder - from files 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash2       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s2 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Nm" ascii
    $s3 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4 = "),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){r" ascii
    $s5 = " fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}