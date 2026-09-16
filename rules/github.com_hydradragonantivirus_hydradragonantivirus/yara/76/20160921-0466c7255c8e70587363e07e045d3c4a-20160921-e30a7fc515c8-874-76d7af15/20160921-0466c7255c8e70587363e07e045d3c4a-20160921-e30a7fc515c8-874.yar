rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_e30a7fc515c8_874 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1  = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f00" ascii
    $s2  = "000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs" ascii
    $s3  = "n\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s4  = "s\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s5  = "ction f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){retu" ascii
    $s6  = "(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s7  = "eturn \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})()" ascii
    $s8  = ",(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s9  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f" ascii
    $s10 = "(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){r" ascii
    $s11 = "rn \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s12 = "urn \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s13 = "n f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"S" ascii
    $s14 = "Db\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(functio" ascii
    $s15 = "unction f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s16 = "tion f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s17 = "000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc" ascii
    $s18 = "eturn \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s19 = "turn \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})()," ascii
    $s20 = "tion f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}