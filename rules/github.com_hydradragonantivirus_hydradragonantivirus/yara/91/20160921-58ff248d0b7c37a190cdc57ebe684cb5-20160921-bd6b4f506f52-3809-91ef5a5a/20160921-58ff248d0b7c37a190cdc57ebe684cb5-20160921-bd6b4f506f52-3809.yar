rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_bd6b4f506f52_3809 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})()" ascii
    $s2 = "on fuck(){return \"KVh\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s3 = "urn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s4 = "rn \"DAa\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s5 = ")(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s6 = "ck(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}