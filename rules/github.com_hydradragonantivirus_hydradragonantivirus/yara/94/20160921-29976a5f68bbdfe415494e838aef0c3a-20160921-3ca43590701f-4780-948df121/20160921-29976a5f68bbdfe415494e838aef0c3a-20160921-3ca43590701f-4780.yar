rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_3ca43590701f_4780 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash3       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"

  strings:
    $s1 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(function f000(){re" ascii
    $s3 = "ion f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s4 = "function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){r" ascii
    $s5 = "\"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}