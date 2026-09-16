rule TTP_XOR_MULT_DOSStub_a67b {
  strings:
    $key_a67b = { f2 13 [2] 86 0b [2] c1 09 [2] 86 18 [2] c8 14 [2] c4 1e [2] d3 15 [2] c8 5b [2] f5 }

  condition:
    any of them
}