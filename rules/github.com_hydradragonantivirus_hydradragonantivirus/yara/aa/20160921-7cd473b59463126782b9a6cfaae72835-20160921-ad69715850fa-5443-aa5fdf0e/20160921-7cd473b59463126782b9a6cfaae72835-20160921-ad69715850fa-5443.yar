rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_ad69715850fa_5443 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "turn \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})()," ascii
    $s2 = "function f000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s3 = "\"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s4 = "){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}