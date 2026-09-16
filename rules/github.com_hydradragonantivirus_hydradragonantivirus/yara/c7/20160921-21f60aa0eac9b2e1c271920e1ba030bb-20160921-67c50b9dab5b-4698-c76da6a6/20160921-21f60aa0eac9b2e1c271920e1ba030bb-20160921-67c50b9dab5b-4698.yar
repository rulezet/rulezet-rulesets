rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_67c50b9dab5b_4698 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s2 = "ion f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s3 = "(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s4 = ")(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000" ascii
    $s5 = "{return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}