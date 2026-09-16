rule TTP_XOR_MULT_DOSStub_5186 {
  strings:
    $key_5186 = { 05 ee [2] 71 f6 [2] 36 f4 [2] 71 e5 [2] 3f e9 [2] 33 e3 [2] 24 e8 [2] 3f a6 [2] 02 }

  condition:
    any of them
}