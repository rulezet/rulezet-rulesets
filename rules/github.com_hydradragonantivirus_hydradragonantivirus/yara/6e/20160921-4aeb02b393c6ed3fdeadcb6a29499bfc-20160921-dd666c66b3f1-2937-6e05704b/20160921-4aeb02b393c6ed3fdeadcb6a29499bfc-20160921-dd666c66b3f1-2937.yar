rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160921_dd666c66b3f1_2937 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "a\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s2 = "\"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s3 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s4 = "\"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s5 = "000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc" ascii
    $s6 = "GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s7 = "0(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}