rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_fa89d54bd5a7_5632 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"" ascii
    $s2 = "),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck()" ascii
    $s3 = "})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuc" ascii
    $s4 = "{return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(" ascii
    $s5 = "(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}