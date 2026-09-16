rule TTP_XOR_MULT_DOSStub_a146 {
  strings:
    $key_a146 = { f5 2e [2] 81 36 [2] c6 34 [2] 81 25 [2] cf 29 [2] c3 23 [2] d4 28 [2] cf 66 [2] f2 }

  condition:
    any of them
}