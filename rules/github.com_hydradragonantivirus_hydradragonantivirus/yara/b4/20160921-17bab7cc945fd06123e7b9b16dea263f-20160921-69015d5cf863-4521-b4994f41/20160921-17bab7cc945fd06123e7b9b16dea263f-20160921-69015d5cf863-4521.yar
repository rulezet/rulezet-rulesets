rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_69015d5cf863_4521 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash4       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash5       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash6       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f0" ascii
    $s2 = "){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})" ascii
    $s3 = "eturn \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4 = "tion f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s5 = "Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}