rule _20160921_b1a0d856c15e8cb36e6ba699332db942_20160921_c07f026b9458_4026 {
  meta:
    description = "datamaliciousorder - from files 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash2       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){re" ascii
    $s2 = "on fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s3 = "n \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s4 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s5 = " \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(funct" ascii
    $s6 = "ction fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}