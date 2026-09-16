rule TTP_XOR_MULT_DOSStub_a720 {
  strings:
    $key_a720 = { f3 48 [2] 87 50 [2] c0 52 [2] 87 43 [2] c9 4f [2] c5 45 [2] d2 4e [2] c9 00 [2] f4 }

  condition:
    any of them
}