rule TTP_XOR_MULT_DOSStub_a6f1 {
  strings:
    $key_a6f1 = { f2 99 [2] 86 81 [2] c1 83 [2] 86 92 [2] c8 9e [2] c4 94 [2] d3 9f [2] c8 d1 [2] f5 }

  condition:
    any of them
}