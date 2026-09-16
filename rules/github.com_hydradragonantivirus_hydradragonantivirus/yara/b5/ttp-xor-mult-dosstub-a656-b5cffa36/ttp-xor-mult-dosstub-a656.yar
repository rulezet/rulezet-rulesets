rule TTP_XOR_MULT_DOSStub_a656 {
  strings:
    $key_a656 = { f2 3e [2] 86 26 [2] c1 24 [2] 86 35 [2] c8 39 [2] c4 33 [2] d3 38 [2] c8 76 [2] f5 }

  condition:
    any of them
}