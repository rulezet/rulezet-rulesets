rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_fec97a223836_5082 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s2 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"U" ascii
    $s3 = "uck(){return \"ZLd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s4 = "n \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s5 = "rn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}