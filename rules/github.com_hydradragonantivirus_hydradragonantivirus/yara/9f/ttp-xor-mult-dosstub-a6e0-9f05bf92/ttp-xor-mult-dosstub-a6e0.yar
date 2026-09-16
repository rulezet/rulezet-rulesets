rule TTP_XOR_MULT_DOSStub_a6e0 {
  strings:
    $key_a6e0 = { f2 88 [2] 86 90 [2] c1 92 [2] 86 83 [2] c8 8f [2] c4 85 [2] d3 8e [2] c8 c0 [2] f5 }

  condition:
    any of them
}