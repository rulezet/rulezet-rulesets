rule _20160921_7caba45960de8ab0904dc3a8514f2614_20160921_8c8c9fad8af6_5438 {
  meta:
    description = "datamaliciousorder - from files 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash2       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(functi" ascii
    $s2 = "urn \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s4 = "k(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\"" ascii
    $s5 = "(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}