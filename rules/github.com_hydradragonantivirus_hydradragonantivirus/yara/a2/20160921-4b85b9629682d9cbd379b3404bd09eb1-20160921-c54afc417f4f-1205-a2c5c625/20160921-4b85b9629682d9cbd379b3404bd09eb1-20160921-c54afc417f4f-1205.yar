rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_c54afc417f4f_1205 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1  = "return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})()" ascii
    $s2  = "tion f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){retur" ascii
    $s3  = "return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4  = "),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000()" ascii
    $s5  = "unction f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s6  = "ion f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s7  = "\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"EZu\";})(),(function " ascii
    $s8  = "ion f000(){return \"NBs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s9  = "turn \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"DIa\";})()" ascii
    $s10 = "urn \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s11 = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"DIa\";})(),(function f000" ascii
    $s12 = "nction f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"WIj\";})(),(function f000(){retur" ascii
    $s13 = "function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){ret" ascii
    $s14 = "rn \"Yv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s15 = "rn \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sv\";})(),(f" ascii
    $s16 = "\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TKl\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}