rule TTP_XOR_MULT_DOSStub_1580 {
  strings:
    $key_1580 = { 41 e8 [2] 35 f0 [2] 72 f2 [2] 35 e3 [2] 7b ef [2] 77 e5 [2] 60 ee [2] 7b a0 [2] 46 }

  condition:
    any of them
}