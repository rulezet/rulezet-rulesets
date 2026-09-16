rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_24a000738e40_1187 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash4       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash5       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash6       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1  = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"HJm\"" ascii
    $s2  = "(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){r" ascii
    $s3  = "\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s4  = "),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(function f000(" ascii
    $s5  = "rn \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(f" ascii
    $s6  = "n \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mt\";})(),(fun" ascii
    $s7  = "unction f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s8  = "turn \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})()," ascii
    $s9  = "p\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function " ascii
    $s10 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s11 = " f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"G" ascii
    $s12 = "function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){ret" ascii
    $s13 = "urn \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(fu" ascii
    $s14 = "00(){return \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\"" ascii
    $s15 = "rn \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(fun" ascii
    $s16 = "return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}