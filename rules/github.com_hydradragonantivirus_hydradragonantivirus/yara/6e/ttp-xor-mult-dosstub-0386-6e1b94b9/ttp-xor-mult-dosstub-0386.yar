rule TTP_XOR_MULT_DOSStub_0386 {
  strings:
    $key_0386 = { 57 ee [2] 23 f6 [2] 64 f4 [2] 23 e5 [2] 6d e9 [2] 61 e3 [2] 76 e8 [2] 6d a6 [2] 50 }

  condition:
    any of them
}