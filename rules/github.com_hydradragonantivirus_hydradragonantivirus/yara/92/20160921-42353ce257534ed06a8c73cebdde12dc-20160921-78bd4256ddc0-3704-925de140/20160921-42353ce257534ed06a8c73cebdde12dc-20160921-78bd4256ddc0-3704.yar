rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_78bd4256ddc0_3704 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash3       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s2 = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retu" ascii
    $s3 = "fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"U" ascii
    $s4 = "uck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s6 = "uck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}