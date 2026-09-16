rule TTP_XOR_MULT_DOSStub_42a5 {
  strings:
    $key_42a5 = { 16 cd [2] 62 d5 [2] 25 d7 [2] 62 c6 [2] 2c ca [2] 20 c0 [2] 37 cb [2] 2c 85 [2] 11 }

  condition:
    any of them
}