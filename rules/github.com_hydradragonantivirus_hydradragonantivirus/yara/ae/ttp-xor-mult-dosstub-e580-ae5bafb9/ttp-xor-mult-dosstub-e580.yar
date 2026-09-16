rule TTP_XOR_MULT_DOSStub_e580 {
  strings:
    $key_e580 = { b1 e8 [2] c5 f0 [2] 82 f2 [2] c5 e3 [2] 8b ef [2] 87 e5 [2] 90 ee [2] 8b a0 [2] b6 }

  condition:
    any of them
}