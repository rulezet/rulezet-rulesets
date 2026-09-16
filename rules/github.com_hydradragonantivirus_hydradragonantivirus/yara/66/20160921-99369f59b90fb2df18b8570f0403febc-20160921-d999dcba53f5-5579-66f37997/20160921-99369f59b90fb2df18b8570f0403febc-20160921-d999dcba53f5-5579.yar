rule _20160921_99369f59b90fb2df18b8570f0403febc_20160921_d999dcba53f5_5579 {
  meta:
    description = "datamaliciousorder - from files 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "0(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\"" ascii
    $s2 = "ction f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){retu" ascii
    $s3 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})" ascii
    $s4 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";}" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}