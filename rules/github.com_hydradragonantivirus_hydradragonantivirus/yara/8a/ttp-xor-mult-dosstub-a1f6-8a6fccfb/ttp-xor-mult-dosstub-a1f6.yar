rule TTP_XOR_MULT_DOSStub_a1f6 {
  strings:
    $key_a1f6 = { f5 9e [2] 81 86 [2] c6 84 [2] 81 95 [2] cf 99 [2] c3 93 [2] d4 98 [2] cf d6 [2] f2 }

  condition:
    any of them
}