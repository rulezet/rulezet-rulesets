rule TTP_XOR_MULT_DOSStub_3580 {
  strings:
    $key_3580 = { 61 e8 [2] 15 f0 [2] 52 f2 [2] 15 e3 [2] 5b ef [2] 57 e5 [2] 40 ee [2] 5b a0 [2] 66 }

  condition:
    any of them
}