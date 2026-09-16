rule _20160922_e3f5fbc84de17ad7f507fc3f34b8151f_20160922_edfdc00dbdbb_4083 {
  meta:
    description = "datamaliciousorder - from files 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})()" ascii
    $s2 = "(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";}" ascii
    $s3 = "n f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return " ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})()" ascii
    $s6 = "j\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}