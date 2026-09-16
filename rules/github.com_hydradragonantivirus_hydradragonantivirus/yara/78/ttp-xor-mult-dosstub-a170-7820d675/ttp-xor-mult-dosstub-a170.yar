rule TTP_XOR_MULT_DOSStub_a170 {
  strings:
    $key_a170 = { f5 18 [2] 81 00 [2] c6 02 [2] 81 13 [2] cf 1f [2] c3 15 [2] d4 1e [2] cf 50 [2] f2 }

  condition:
    any of them
}