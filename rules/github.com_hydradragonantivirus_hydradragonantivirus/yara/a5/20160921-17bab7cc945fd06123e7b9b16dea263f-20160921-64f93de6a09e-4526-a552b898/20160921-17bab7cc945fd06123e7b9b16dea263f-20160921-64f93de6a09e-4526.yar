rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_64f93de6a09e_4526 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash3       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash4       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash5       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"
    hash6       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){re" ascii
    $s2 = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"T" ascii
    $s3 = " \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s4 = "{return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";}" ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}