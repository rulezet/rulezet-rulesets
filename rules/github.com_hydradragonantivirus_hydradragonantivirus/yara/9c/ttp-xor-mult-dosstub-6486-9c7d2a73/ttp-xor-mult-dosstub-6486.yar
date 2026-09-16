rule TTP_XOR_MULT_DOSStub_6486 {
  strings:
    $key_6486 = { 30 ee [2] 44 f6 [2] 03 f4 [2] 44 e5 [2] 0a e9 [2] 06 e3 [2] 11 e8 [2] 0a a6 [2] 37 }

  condition:
    any of them
}