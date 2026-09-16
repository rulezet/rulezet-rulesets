rule _20160921_a7daa1622ff2bc3dccfc20f622902f7b_20160921_d72e05128386_4014 {
  meta:
    description = "datamaliciousorder - from files 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"
    hash3       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = "){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";}" ascii
    $s2 = "p\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s3 = "turn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s5 = " \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s6 = "unction fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}