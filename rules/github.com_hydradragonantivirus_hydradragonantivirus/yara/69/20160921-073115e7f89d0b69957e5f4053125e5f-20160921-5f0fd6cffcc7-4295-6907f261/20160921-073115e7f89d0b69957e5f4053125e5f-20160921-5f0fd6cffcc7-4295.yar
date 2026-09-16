rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_5f0fd6cffcc7_4295 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"

  strings:
    $s1 = "Gn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(functi" ascii
    $s2 = "(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = "\"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = "nction f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s5 = "00(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}