rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_446be595a498_3365 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash3       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"

  strings:
    $s1 = "(){return \"DAa\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\"" ascii
    $s2 = " \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s3 = "ction fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return" ascii
    $s4 = "fuck(){return \"To\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s5 = "urn \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(" ascii
    $s6 = "(){return \"Xg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}