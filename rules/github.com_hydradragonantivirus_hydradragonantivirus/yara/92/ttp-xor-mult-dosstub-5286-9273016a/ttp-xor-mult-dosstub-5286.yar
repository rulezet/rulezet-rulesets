rule TTP_XOR_MULT_DOSStub_5286 {
  strings:
    $key_5286 = { 06 ee [2] 72 f6 [2] 35 f4 [2] 72 e5 [2] 3c e9 [2] 30 e3 [2] 27 e8 [2] 3c a6 [2] 01 }

  condition:
    any of them
}