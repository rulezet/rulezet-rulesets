rule TTP_XOR_MULT_DOSStub_a156 {
  strings:
    $key_a156 = { f5 3e [2] 81 26 [2] c6 24 [2] 81 35 [2] cf 39 [2] c3 33 [2] d4 38 [2] cf 76 [2] f2 }

  condition:
    any of them
}