rule TTP_XOR_MULT_DOSStub_b680 {
  strings:
    $key_b680 = { e2 e8 [2] 96 f0 [2] d1 f2 [2] 96 e3 [2] d8 ef [2] d4 e5 [2] c3 ee [2] d8 a0 [2] e5 }

  condition:
    any of them
}