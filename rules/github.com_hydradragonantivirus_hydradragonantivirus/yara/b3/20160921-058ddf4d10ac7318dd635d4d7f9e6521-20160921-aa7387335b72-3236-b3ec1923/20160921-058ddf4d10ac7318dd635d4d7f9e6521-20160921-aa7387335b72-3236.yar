rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_aa7387335b72_3236 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})" ascii
    $s2 = "y\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s3 = "),(function fuck(){return \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Pc\";})(),(function fuck()" ascii
    $s4 = "{return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retur" ascii
    $s6 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}