rule _20160921_9dc96613aa4c64f92e4ff218607f50d0_20160921_bd6b4f506f52_5591 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dc96613aa4c64f92e4ff218607f50d0.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash3       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})()," ascii
    $s2 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s3 = "s\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function " ascii
    $s4 = "return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = "turn \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}