rule _20160921_b1a0d856c15e8cb36e6ba699332db942_20160921_c07f026b9458_4027 {
  meta:
    description = "datamaliciousorder - from files 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash2       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash3       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "turn \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s2 = ")(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s4 = "IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(functi" ascii
    $s5 = "n fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s6 = "eturn \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}