rule _20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d_20160921_e2617d9e437c_2152 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1 = "return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(" ascii
    $s2 = " \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s3 = "\"Et\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = "),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s5 = "ion fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s6 = "on fuck(){return \"GWo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s7 = "\"MIl\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(func" ascii
    $s8 = "){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})" ascii
    $s9 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}