rule TTP_XOR_MULT_DOSStub_a62b {
  strings:
    $key_a62b = { f2 43 [2] 86 5b [2] c1 59 [2] 86 48 [2] c8 44 [2] c4 4e [2] d3 45 [2] c8 0b [2] f5 }

  condition:
    any of them
}