rule TTP_XOR_MULT_DOSStub_1280 {
  strings:
    $key_1280 = { 46 e8 [2] 32 f0 [2] 75 f2 [2] 32 e3 [2] 7c ef [2] 70 e5 [2] 67 ee [2] 7c a0 [2] 41 }

  condition:
    any of them
}