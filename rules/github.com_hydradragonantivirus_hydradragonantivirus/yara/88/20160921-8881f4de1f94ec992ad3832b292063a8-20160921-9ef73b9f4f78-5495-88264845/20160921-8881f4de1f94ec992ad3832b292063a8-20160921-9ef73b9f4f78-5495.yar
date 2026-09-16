rule _20160921_8881f4de1f94ec992ad3832b292063a8_20160921_9ef73b9f4f78_5495 {
  meta:
    description = "datamaliciousorder - from files 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash2       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"

  strings:
    $s1 = "})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s2 = "Ts\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function " ascii
    $s3 = "urn \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s4 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck" ascii
    $s5 = "ion fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}