rule TTP_XOR_MULT_DOSStub_a1d4 {
  strings:
    $key_a1d4 = { f5 bc [2] 81 a4 [2] c6 a6 [2] 81 b7 [2] cf bb [2] c3 b1 [2] d4 ba [2] cf f4 [2] f2 }

  condition:
    any of them
}