rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_d47b4a8df439_3706 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"

  strings:
    $s1 = " \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"ZIi\";})(),(fun" ascii
    $s2 = "nction f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s3 = "00(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";" ascii
    $s4 = "rn \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s5 = "ion f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s6 = "(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}