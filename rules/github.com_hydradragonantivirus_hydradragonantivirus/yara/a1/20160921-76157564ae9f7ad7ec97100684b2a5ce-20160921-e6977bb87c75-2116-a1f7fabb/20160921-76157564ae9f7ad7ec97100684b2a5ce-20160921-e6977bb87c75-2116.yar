rule _20160921_76157564ae9f7ad7ec97100684b2a5ce_20160921_e6977bb87c75_2116 {
  meta:
    description = "datamaliciousorder - from files 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "n \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s2 = "(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck()" ascii
    $s3 = "urn \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s4 = "{return \"Hs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s5 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s6 = "eturn \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s7 = "uck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx" ascii
    $s8 = "function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retu" ascii
    $s9 = "rn \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}