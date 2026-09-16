rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_718cbfc32cb1_4787 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash3       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1 = "uck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd" ascii
    $s2 = "})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck" ascii
    $s3 = ";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fu" ascii
    $s4 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(functi" ascii
    $s5 = "urn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}