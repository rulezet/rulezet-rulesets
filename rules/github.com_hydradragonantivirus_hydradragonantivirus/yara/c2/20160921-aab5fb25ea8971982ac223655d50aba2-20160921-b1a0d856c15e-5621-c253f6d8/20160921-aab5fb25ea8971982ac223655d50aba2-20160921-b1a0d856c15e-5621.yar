rule _20160921_aab5fb25ea8971982ac223655d50aba2_20160921_b1a0d856c15e_5621 {
  meta:
    description = "datamaliciousorder - from files 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = "})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fu" ascii
    $s2 = "\"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(func" ascii
    $s3 = "return \"Et\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s4 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Zy\"" ascii
    $s5 = " \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}