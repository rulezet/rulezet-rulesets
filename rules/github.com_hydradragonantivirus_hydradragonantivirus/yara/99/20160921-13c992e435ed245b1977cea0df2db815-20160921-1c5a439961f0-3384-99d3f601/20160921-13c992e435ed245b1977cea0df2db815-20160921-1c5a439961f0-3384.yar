rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_1c5a439961f0_3384 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_1c5a439961f0eccee5312fdbb892fb0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"

  strings:
    $s1 = "rn \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s2 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s3 = "tion f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(),(function f000(){retur" ascii
    $s4 = "n f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s5 = "ion f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s6 = " f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}