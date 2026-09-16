rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_24a000738e40_545 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"

  strings:
    $s1  = "return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(" ascii
    $s2  = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"B" ascii
    $s3  = "b\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s4  = "eturn \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"RPt\";})()" ascii
    $s5  = "i\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s7  = "nction f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s8  = "Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s9  = ")(),(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yz\";})(),(function f000(" ascii
    $s10 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s11 = "rn \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s12 = "unction f000(){return \"Uo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s13 = "000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp" ascii
    $s14 = "Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s15 = "tion f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii
    $s16 = "00(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn" ascii
    $s17 = "unction f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s18 = " \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"ZGq\";})(),(func" ascii
    $s19 = " f000(){return \"UEg\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s20 = "0(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}