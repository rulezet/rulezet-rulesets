rule _20160921_615f98dbcc83e57c9789ba9d89e188d0_20160921_65ff2a70ce98_5295 {
  meta:
    description = "datamaliciousorder - from files 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash2       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"

  strings:
    $s1 = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s2 = "n fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"U" ascii
    $s3 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s4 = "ck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\"" ascii
    $s5 = " \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Mw\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}