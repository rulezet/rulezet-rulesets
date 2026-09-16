rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_5d6863feab41_1469 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_5d6863feab411af8217516a1b111aa40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"

  strings:
    $s1  = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f00" ascii
    $s2  = "){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";}" ascii
    $s3  = "GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(functio" ascii
    $s4  = "n f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s5  = "0(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\"" ascii
    $s6  = " f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MD" ascii
    $s7  = "ion f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s8  = "{return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(" ascii
    $s9  = "function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s10 = "eturn \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})()," ascii
    $s11 = "QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function" ascii
    $s12 = "turn \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s13 = "ction f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}