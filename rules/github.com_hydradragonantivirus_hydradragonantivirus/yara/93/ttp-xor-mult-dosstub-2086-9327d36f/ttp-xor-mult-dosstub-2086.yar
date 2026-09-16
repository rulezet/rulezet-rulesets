rule TTP_XOR_MULT_DOSStub_2086 {
  strings:
    $key_2086 = { 74 ee [2] 00 f6 [2] 47 f4 [2] 00 e5 [2] 4e e9 [2] 42 e3 [2] 55 e8 [2] 4e a6 [2] 73 }

  condition:
    any of them
}