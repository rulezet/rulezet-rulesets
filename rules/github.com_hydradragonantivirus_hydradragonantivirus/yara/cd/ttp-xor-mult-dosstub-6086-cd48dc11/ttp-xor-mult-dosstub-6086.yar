rule TTP_XOR_MULT_DOSStub_6086 {
  strings:
    $key_6086 = { 34 ee [2] 40 f6 [2] 07 f4 [2] 40 e5 [2] 0e e9 [2] 02 e3 [2] 15 e8 [2] 0e a6 [2] 33 }

  condition:
    any of them
}