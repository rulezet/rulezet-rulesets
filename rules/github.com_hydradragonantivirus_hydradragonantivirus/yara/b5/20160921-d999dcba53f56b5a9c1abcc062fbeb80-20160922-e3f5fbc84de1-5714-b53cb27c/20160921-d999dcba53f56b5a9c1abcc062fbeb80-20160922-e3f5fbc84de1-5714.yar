rule _20160921_d999dcba53f56b5a9c1abcc062fbeb80_20160922_e3f5fbc84de1_5714 {
  meta:
    description = "datamaliciousorder - from files 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SG" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\"" ascii
    $s3 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s4 = "RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(funct" ascii
    $s5 = "\"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}