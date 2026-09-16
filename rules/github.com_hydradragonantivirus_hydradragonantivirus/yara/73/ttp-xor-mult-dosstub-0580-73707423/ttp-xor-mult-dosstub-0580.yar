rule TTP_XOR_MULT_DOSStub_0580 {
  strings:
    $key_0580 = { 51 e8 [2] 25 f0 [2] 62 f2 [2] 25 e3 [2] 6b ef [2] 67 e5 [2] 70 ee [2] 6b a0 [2] 56 }

  condition:
    any of them
}