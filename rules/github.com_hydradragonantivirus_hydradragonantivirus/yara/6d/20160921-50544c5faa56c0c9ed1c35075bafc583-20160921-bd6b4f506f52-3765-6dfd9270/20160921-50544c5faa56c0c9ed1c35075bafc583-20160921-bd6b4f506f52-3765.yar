rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_bd6b4f506f52_3765 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(" ascii
    $s2 = "),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s3 = ")(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck()" ascii
    $s4 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){" ascii
    $s5 = "\"Qh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(funct" ascii
    $s6 = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}