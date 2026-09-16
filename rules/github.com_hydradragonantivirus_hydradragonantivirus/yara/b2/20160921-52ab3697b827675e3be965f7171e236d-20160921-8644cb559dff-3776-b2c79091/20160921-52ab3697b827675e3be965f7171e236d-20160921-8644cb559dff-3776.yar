rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_3776 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){retu" ascii
    $s2 = "){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})" ascii
    $s3 = "(){return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\"" ascii
    $s4 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii
    $s5 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fuck" ascii
    $s6 = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}