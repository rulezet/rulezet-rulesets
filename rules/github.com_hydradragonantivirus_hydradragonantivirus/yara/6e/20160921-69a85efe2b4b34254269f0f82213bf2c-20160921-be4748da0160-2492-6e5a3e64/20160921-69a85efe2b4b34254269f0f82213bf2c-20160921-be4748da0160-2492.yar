rule _20160921_69a85efe2b4b34254269f0f82213bf2c_20160921_be4748da0160_2492 {
  meta:
    description = "datamaliciousorder - from files 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(functi" ascii
    $s2 = "ion fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s3 = "(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZWu\"" ascii
    $s4 = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii
    $s5 = "return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s6 = "\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function f" ascii
    $s7 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"FJs\";})(),(functio" ascii
    $s8 = "unction fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}