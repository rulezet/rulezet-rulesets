rule _20160921_30902cdec8afbffc64d0c0cd57e17570_20160921_c58f55b02ed5_2031 {
  meta:
    description = "datamaliciousorder - from files 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash2       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"
    hash3       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1 = "ck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MIl" ascii
    $s2 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(fun" ascii
    $s3 = "(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";" ascii
    $s4 = "function fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii
    $s5 = "\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function f" ascii
    $s6 = "\"Ai\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s7 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ZLd\";})(),(func" ascii
    $s8 = "k(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe" ascii
    $s9 = "(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}