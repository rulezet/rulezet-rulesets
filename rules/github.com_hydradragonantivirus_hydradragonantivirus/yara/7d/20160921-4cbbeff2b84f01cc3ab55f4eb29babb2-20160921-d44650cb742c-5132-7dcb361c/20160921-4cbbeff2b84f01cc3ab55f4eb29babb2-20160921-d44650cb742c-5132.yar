rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_d44650cb742c_5132 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "uck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy" ascii
    $s2 = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s3 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s4 = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fu" ascii
    $s5 = " fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}