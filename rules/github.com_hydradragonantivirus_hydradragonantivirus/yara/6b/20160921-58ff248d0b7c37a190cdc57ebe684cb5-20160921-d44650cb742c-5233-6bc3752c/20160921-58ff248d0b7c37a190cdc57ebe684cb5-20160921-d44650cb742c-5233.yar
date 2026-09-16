rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_d44650cb742c_5233 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1 = "(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\"" ascii
    $s2 = "ck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s3 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s4 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){re" ascii
    $s5 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}