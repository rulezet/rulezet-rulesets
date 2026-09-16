rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_510713862e5c_3569 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash3       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"

  strings:
    $s1 = "n \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})" ascii
    $s3 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s4 = "k(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\"" ascii
    $s5 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s6 = "k(){return \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}