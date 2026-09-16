rule TTP_XOR_MULT_DOSStub_66a5 {
  strings:
    $key_66a5 = { 32 cd [2] 46 d5 [2] 01 d7 [2] 46 c6 [2] 08 ca [2] 04 c0 [2] 13 cb [2] 08 85 [2] 35 }

  condition:
    any of them
}