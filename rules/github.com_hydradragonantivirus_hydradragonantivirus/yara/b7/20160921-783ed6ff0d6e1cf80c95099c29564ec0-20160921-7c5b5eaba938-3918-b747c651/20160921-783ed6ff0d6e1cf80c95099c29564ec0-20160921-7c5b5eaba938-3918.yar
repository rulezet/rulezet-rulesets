rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_7c5b5eaba938_3918 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_af22e174703ebae0fa1368fd471dba37.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash3       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"
    hash4       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "ck(){return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj" ascii
    $s2 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii
    $s3 = "n \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(fun" ascii
    $s4 = "\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s5 = "k(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";" ascii
    $s6 = "})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}