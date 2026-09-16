rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_50b14bf13c50_4998 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash3       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash4       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash5       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash6       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash7       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash8       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck()" ascii
    $s2 = "turn \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3 = "ck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\"" ascii
    $s4 = "n \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(fun" ascii
    $s5 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}