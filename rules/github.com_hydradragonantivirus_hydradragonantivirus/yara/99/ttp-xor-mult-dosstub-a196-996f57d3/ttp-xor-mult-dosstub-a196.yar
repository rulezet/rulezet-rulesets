rule TTP_XOR_MULT_DOSStub_a196 {
  strings:
    $key_a196 = { f5 fe [2] 81 e6 [2] c6 e4 [2] 81 f5 [2] cf f9 [2] c3 f3 [2] d4 f8 [2] cf b6 [2] f2 }

  condition:
    any of them
}