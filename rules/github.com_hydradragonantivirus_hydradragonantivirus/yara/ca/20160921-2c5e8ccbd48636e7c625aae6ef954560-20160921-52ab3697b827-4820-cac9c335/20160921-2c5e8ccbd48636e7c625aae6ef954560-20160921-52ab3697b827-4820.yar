rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_52ab3697b827_4820 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash3       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash4       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"

  strings:
    $s1 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s3 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s4 = "n fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"I" ascii
    $s5 = "){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}