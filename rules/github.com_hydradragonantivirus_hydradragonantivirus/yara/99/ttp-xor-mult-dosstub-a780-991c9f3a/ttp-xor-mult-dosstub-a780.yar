rule TTP_XOR_MULT_DOSStub_a780 {
  strings:
    $key_a780 = { f3 e8 [2] 87 f0 [2] c0 f2 [2] 87 e3 [2] c9 ef [2] c5 e5 [2] d2 ee [2] c9 a0 [2] f4 }

  condition:
    any of them
}