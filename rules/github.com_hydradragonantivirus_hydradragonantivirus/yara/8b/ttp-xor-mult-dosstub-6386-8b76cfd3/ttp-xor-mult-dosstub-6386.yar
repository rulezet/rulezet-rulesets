rule TTP_XOR_MULT_DOSStub_6386 {
  strings:
    $key_6386 = { 37 ee [2] 43 f6 [2] 04 f4 [2] 43 e5 [2] 0d e9 [2] 01 e3 [2] 16 e8 [2] 0d a6 [2] 30 }

  condition:
    any of them
}