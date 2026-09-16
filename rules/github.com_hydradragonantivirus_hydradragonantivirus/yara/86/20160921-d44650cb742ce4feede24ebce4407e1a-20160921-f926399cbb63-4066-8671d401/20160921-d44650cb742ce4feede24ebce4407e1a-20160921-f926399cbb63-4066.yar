rule _20160921_d44650cb742ce4feede24ebce4407e1a_20160921_f926399cbb63_4066 {
  meta:
    description = "datamaliciousorder - from files 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "{return \"Ai\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s3 = " fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"" ascii
    $s4 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii
    $s5 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){" ascii
    $s6 = "uck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}