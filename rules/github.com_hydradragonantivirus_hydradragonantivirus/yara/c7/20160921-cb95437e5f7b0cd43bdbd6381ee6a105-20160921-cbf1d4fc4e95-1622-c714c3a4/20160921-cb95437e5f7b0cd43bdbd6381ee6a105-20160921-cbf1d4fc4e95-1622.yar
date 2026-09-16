rule _20160921_cb95437e5f7b0cd43bdbd6381ee6a105_20160921_cbf1d4fc4e95_1622 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"
    hash2       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"

  strings:
    $s1  = "uck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq" ascii
    $s2  = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s3  = "eturn \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Zy\";})(),(f" ascii
    $s4  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Oh\"" ascii
    $s5  = "n \"Ot\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s6  = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(" ascii
    $s7  = "rn \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(fu" ascii
    $s8  = "urn \"Ik\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s9  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return" ascii
    $s10 = "Pu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s11 = "n fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s12 = "IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}