rule _20160921_acea633b73985995ce9764bf94db0972_20160921_d88b1be24c58_5627 {
  meta:
    description = "datamaliciousorder - from files 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash2       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1 = "eturn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s2 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s3 = "function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s4 = "return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})()" ascii
    $s5 = "ck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}