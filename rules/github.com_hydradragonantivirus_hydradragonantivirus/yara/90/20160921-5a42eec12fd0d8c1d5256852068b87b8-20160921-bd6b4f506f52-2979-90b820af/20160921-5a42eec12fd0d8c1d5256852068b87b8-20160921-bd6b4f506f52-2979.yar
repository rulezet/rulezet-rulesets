rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_bd6b4f506f52_2979 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1 = "tion fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return " ascii
    $s2 = "n fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s3 = "eturn \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s4 = "rn \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s5 = "turn \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})()," ascii
    $s6 = "\"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s7 = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}