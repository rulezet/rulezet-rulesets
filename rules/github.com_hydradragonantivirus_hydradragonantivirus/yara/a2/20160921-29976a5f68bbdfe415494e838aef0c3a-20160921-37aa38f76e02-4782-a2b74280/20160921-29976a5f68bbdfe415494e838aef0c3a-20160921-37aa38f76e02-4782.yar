rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_37aa38f76e02_4782 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_37aa38f76e02afb64903280105ce4597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";}" ascii
    $s2 = "nction f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s3 = "00(){return \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl" ascii
    $s4 = "tion f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}