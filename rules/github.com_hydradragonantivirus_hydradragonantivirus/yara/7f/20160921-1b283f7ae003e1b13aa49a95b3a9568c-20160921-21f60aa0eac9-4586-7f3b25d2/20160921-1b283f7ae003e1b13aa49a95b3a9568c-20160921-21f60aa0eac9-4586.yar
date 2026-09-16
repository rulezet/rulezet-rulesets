rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_21f60aa0eac9_4586 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"

  strings:
    $s1 = "q\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function" ascii
    $s2 = "){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";" ascii
    $s3 = "nction f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){retu" ascii
    $s4 = "f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw" ascii
    $s5 = "{return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}