rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_3e5e21af311d_2804 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"

  strings:
    $s1 = "on f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s2 = "urn \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(" ascii
    $s3 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f00" ascii
    $s4 = "),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000()" ascii
    $s5 = "ction f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s6 = "\"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s7 = "\"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}