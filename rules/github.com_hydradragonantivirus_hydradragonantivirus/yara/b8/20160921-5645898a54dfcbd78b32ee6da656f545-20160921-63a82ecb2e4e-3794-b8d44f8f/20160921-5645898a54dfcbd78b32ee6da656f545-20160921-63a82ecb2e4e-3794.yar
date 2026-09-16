rule _20160921_5645898a54dfcbd78b32ee6da656f545_20160921_63a82ecb2e4e_3794 {
  meta:
    description = "datamaliciousorder - from files 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash2       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"

  strings:
    $s1 = "k(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe" ascii
    $s2 = "unction fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){re" ascii
    $s3 = "(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\"" ascii
    $s4 = "Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(functi" ascii
    $s5 = "UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s6 = "\"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}