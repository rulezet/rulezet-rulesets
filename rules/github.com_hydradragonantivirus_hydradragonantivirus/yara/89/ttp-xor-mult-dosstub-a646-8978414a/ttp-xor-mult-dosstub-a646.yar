rule TTP_XOR_MULT_DOSStub_a646 {
  strings:
    $key_a646 = { f2 2e [2] 86 36 [2] c1 34 [2] 86 25 [2] c8 29 [2] c4 23 [2] d3 28 [2] c8 66 [2] f5 }

  condition:
    any of them
}