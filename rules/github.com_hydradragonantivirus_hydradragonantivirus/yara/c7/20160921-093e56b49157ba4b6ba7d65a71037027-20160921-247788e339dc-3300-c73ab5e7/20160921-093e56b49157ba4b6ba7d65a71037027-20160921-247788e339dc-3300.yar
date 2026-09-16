rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_3300 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash4       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash5       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return " ascii
    $s2 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck()" ascii
    $s3 = "ck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np" ascii
    $s4 = "(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s5 = "){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s6 = "urn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}