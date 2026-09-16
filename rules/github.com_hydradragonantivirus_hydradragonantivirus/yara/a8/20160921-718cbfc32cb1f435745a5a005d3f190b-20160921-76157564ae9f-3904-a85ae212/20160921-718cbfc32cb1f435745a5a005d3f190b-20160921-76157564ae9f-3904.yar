rule _20160921_718cbfc32cb1f435745a5a005d3f190b_20160921_76157564ae9f_3904 {
  meta:
    description = "datamaliciousorder - from files 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_76157564ae9f7ad7ec97100684b2a5ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash2       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"

  strings:
    $s1 = "function fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s2 = "(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"PDf\";})(),(function fuck()" ascii
    $s3 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(func" ascii
    $s4 = "\"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s5 = " \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s6 = ")(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}