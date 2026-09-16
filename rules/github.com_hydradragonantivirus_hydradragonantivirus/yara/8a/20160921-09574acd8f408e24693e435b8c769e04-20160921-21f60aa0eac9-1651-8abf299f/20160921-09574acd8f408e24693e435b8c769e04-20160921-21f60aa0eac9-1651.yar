rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_21f60aa0eac9_1651 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash3       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash4       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash5       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1  = "unction f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s2  = "\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function " ascii
    $s3  = "0(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";}" ascii
    $s4  = "tion f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){retur" ascii
    $s5  = "return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(" ascii
    $s6  = "00(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s7  = "(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){re" ascii
    $s8  = "ction f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s9  = " \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s10 = "(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s11 = "{return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}