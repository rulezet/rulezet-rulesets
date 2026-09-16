rule _20160921_6bf1e6b71f68264911cd95f601a6cc98_20160921_a8b3df7e98e8_3876 {
  meta:
    description = "datamaliciousorder - from files 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash2       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash3       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash4       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash5       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash6       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"
    hash7       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(fun" ascii
    $s2 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0" ascii
    $s3 = "e\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function f" ascii
    $s4 = "\"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(funct" ascii
    $s5 = "(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){ret" ascii
    $s6 = "tion fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}