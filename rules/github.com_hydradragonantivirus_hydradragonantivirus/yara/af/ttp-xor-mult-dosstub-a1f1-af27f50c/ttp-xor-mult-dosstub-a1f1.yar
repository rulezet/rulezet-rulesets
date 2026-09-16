rule TTP_XOR_MULT_DOSStub_a1f1 {
  strings:
    $key_a1f1 = { f5 99 [2] 81 81 [2] c6 83 [2] 81 92 [2] cf 9e [2] c3 94 [2] d4 9f [2] cf d1 [2] f2 }

  condition:
    any of them
}