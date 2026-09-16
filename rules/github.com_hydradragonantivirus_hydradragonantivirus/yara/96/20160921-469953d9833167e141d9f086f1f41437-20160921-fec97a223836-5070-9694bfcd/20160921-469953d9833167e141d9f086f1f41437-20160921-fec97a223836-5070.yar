rule _20160921_469953d9833167e141d9f086f1f41437_20160921_fec97a223836_5070 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(" ascii
    $s2 = "return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s3 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s4 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return" ascii
    $s5 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}