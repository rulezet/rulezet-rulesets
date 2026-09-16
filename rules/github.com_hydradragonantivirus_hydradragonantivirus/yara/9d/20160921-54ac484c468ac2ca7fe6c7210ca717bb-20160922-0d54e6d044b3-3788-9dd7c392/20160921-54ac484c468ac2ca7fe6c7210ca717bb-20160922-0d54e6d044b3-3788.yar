rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160922_0d54e6d044b3_3788 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"

  strings:
    $s1 = "),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000()" ascii
    $s2 = "turn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})()," ascii
    $s3 = "function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s4 = "ction f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s5 = "n \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(fun" ascii
    $s6 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}