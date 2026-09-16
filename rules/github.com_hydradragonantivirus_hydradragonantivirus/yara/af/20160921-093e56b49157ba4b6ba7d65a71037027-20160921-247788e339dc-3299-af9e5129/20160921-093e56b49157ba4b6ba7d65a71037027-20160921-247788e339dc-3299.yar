rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_3299 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash4       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(" ascii
    $s2 = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function" ascii
    $s3 = ")(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s4 = "on fuck(){return \"Ve\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"" ascii
    $s5 = "(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\"" ascii
    $s6 = "Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}