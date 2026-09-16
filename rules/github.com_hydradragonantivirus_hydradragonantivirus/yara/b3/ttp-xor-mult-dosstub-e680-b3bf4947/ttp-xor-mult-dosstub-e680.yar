rule TTP_XOR_MULT_DOSStub_e680 {
  strings:
    $key_e680 = { b2 e8 [2] c6 f0 [2] 81 f2 [2] c6 e3 [2] 88 ef [2] 84 e5 [2] 93 ee [2] 88 a0 [2] b5 }

  condition:
    any of them
}