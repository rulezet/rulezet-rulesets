rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_989b05bf7416_2444 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash4       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"
    hash5       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Wy\";})(),(function f00" ascii
    $s3 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(" ascii
    $s4 = "rn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s5 = "turn \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(" ascii
    $s6 = "ion f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s7 = "(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){r" ascii
    $s8 = " f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}