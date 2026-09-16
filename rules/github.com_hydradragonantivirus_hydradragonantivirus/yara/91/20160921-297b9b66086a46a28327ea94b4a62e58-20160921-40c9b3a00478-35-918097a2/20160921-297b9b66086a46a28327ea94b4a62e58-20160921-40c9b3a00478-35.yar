rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_35 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"

  strings:
    $s1  = "00(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\"" ascii
    $s2  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s3  = "turn \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})()," ascii
    $s4  = "ction f000(){return \"Kw\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s5  = "){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";}" ascii
    $s6  = "00(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa" ascii
    $s7  = "function f000(){return \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s8  = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s9  = "rn \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(fu" ascii
    $s10 = "0(){return \"XTn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s11 = " f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s12 = "turn \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"PTs\";})(),(f" ascii
    $s13 = "turn \"Kw\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii
    $s14 = "){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";}" ascii
    $s15 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function" ascii
    $s16 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Tb\";})(),(function f0" ascii
    $s17 = "Gn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s18 = "\"DNa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s19 = "f000(){return \"BMj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s20 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}