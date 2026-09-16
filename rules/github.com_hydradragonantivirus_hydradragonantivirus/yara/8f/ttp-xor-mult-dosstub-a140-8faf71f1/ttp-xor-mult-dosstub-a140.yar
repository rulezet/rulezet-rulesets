rule TTP_XOR_MULT_DOSStub_a140 {
  strings:
    $key_a140 = { f5 28 [2] 81 30 [2] c6 32 [2] 81 23 [2] cf 2f [2] c3 25 [2] d4 2e [2] cf 60 [2] f2 }

  condition:
    any of them
}