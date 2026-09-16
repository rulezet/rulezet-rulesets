rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_3d83b7982fc5_4816 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash3       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s2 = " fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg" ascii
    $s3 = " \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s4 = "ck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\"" ascii
    $s5 = "Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}