rule TTP_XOR_MULT_DOSStub_a63b {
  strings:
    $key_a63b = { f2 53 [2] 86 4b [2] c1 49 [2] 86 58 [2] c8 54 [2] c4 5e [2] d3 55 [2] c8 1b [2] f5 }

  condition:
    any of them
}