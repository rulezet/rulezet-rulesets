rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_46b3ab412369_225 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_46b3ab412369507850a916abad1e6bf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"

  strings:
    $s1  = "0(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s2  = "on f000(){return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s3  = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s4  = "(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s5  = "turn \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s6  = "000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\"" ascii
    $s7  = "ction f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii
    $s8  = "(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"OMd\";})(),(function f000(" ascii
    $s9  = "return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})()" ascii
    $s10 = "000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Ut\"" ascii
    $s11 = "GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(functi" ascii
    $s12 = "\"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(funct" ascii
    $s13 = "){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"ZFe\";})" ascii
    $s14 = "return \"Oe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})()" ascii
    $s15 = "(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";}" ascii
    $s16 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s17 = "ion f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s18 = "on f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s19 = "urn \"Mu\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s20 = "Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}