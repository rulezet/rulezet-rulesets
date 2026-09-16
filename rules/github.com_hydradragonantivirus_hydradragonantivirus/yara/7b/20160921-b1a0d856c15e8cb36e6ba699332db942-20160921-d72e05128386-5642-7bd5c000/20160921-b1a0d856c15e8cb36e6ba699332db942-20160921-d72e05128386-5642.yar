rule _20160921_b1a0d856c15e8cb36e6ba699332db942_20160921_d72e05128386_5642 {
  meta:
    description = "datamaliciousorder - from files 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"
    hash3       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";" ascii
    $s2 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"" ascii
    $s3 = "on fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = "urn \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s5 = "eturn \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}