rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_7912bf379029_560 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1  = "n \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DYx\";})(),(f" ascii
    $s2  = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s3  = "tion f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii
    $s4  = "n f000(){return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return " ascii
    $s5  = " \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(fu" ascii
    $s6  = " \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s7  = "function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"XTn\";})(),(function f000(){re" ascii
    $s8  = "unction f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii
    $s9  = "),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){" ascii
    $s10 = "f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"HJ" ascii
    $s11 = " f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"M" ascii
    $s12 = "(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})" ascii
    $s13 = " \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s14 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs" ascii
    $s15 = "urn \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s16 = "){return \"Kw\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s17 = "unction f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii
    $s18 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TKl\";})(),(function " ascii
    $s19 = "\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s20 = "\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}