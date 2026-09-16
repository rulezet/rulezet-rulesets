rule _20160921_3214ea252f2a25e018a03ee43ce952f5_20160921_78345276f684_4861 {
  meta:
    description = "datamaliciousorder - from files 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_78345276f684d53628bbcac810994182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"

  strings:
    $s1 = "n \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Et\";})(),(fu" ascii
    $s2 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s3 = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"GJx\";})(),(function fuck()" ascii
    $s4 = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s5 = "{return \"UOe\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}