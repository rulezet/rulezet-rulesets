rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_3294 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash4       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash5       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash6       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "\"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s2 = "k(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\"" ascii
    $s3 = "Cr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s4 = "Ld\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s5 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s6 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}