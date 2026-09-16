rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160921_b15ce64784b0_1600 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"

  strings:
    $s1  = "n f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s2  = "turn \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s3  = "urn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s4  = "w\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5  = "Xg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(functi" ascii
    $s6  = "\"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s7  = "turn \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})()," ascii
    $s8  = "return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s9  = "eturn \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s10 = "{return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})" ascii
    $s11 = "(function f000(){return \"ZIi\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s12 = "0(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}