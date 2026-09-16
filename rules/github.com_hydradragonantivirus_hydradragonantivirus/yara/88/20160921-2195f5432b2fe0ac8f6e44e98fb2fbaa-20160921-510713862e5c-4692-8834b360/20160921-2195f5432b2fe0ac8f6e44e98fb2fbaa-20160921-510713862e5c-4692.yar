rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_510713862e5c_4692 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash3       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash4       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash5       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "k(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s2 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){ret" ascii
    $s3 = "\"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(func" ascii
    $s4 = "urn \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s5 = "(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}