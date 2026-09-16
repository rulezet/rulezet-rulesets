rule TTP_XOR_MULT_DOSStub_1286 {
  strings:
    $key_1286 = { 46 ee [2] 32 f6 [2] 75 f4 [2] 32 e5 [2] 7c e9 [2] 70 e3 [2] 67 e8 [2] 7c a6 [2] 41 }

  condition:
    any of them
}