rule TTP_XOR_MULT_DOSStub_a64b {
  strings:
    $key_a64b = { f2 23 [2] 86 3b [2] c1 39 [2] 86 28 [2] c8 24 [2] c4 2e [2] d3 25 [2] c8 6b [2] f5 }

  condition:
    any of them
}