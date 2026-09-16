rule _20160921_46b3ab412369507850a916abad1e6bf0_20160921_63def3fff7f1_1348 {
  meta:
    description = "datamaliciousorder - from files 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash2       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"

  strings:
    $s1  = "on f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s2  = "eturn \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii
    $s3  = "tion f000(){return \"Uo\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s4  = "0(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MMz\"" ascii
    $s5  = "{return \"Uo\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(" ascii
    $s6  = "0(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s7  = "nction f000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"OMd\";})(),(function f000(){retur" ascii
    $s8  = "return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"YTp\";})()" ascii
    $s9  = "function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){re" ascii
    $s10 = "n\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s11 = "h\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function " ascii
    $s12 = "eturn \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})()" ascii
    $s13 = "y\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function" ascii
    $s14 = "urn \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s15 = "\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}