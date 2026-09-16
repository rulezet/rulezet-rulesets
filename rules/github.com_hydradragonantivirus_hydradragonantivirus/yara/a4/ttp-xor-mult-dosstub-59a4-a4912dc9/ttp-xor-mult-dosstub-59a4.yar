rule TTP_XOR_MULT_DOSStub_59a4 {
  strings:
    $key_59a4 = { 0d cc [2] 79 d4 [2] 3e d6 [2] 79 c7 [2] 37 cb [2] 3b c1 [2] 2c ca [2] 37 84 [2] 0a }

  condition:
    any of them
}