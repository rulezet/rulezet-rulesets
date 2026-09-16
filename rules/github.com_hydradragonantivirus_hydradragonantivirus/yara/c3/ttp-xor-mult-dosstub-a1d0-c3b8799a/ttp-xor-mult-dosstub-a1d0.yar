rule TTP_XOR_MULT_DOSStub_a1d0 {
  strings:
    $key_a1d0 = { f5 b8 [2] 81 a0 [2] c6 a2 [2] 81 b3 [2] cf bf [2] c3 b5 [2] d4 be [2] cf f0 [2] f2 }

  condition:
    any of them
}