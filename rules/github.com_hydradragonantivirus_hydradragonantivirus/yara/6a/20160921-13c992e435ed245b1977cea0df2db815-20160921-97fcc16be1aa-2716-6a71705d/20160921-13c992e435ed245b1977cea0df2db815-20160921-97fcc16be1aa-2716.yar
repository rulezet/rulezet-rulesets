rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_97fcc16be1aa_2716 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = "(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s2 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s4 = "function f000(){return \"Yv\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"TKp\";})(),(function f000(){re" ascii
    $s5 = "f000(){return \"PTi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s6 = "\"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Ml\";})(),(funct" ascii
    $s7 = "KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}