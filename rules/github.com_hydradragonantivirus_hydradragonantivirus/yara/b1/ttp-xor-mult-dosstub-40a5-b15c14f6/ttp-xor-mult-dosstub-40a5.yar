rule TTP_XOR_MULT_DOSStub_40a5 {
  strings:
    $key_40a5 = { 14 cd [2] 60 d5 [2] 27 d7 [2] 60 c6 [2] 2e ca [2] 22 c0 [2] 35 cb [2] 2e 85 [2] 13 }

  condition:
    any of them
}