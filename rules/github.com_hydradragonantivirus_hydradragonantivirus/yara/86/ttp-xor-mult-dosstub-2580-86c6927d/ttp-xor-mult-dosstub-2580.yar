rule TTP_XOR_MULT_DOSStub_2580 {
  strings:
    $key_2580 = { 71 e8 [2] 05 f0 [2] 42 f2 [2] 05 e3 [2] 4b ef [2] 47 e5 [2] 50 ee [2] 4b a0 [2] 76 }

  condition:
    any of them
}