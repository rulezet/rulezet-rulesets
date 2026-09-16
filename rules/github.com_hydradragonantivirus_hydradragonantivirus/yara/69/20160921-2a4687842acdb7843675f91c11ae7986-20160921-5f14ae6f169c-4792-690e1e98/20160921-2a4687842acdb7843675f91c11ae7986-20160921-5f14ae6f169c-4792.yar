rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_5f14ae6f169c_4792 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"
    hash3       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "k(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj" ascii
    $s2 = "eturn \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s3 = "n fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s4 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s5 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}