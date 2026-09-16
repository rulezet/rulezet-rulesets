rule TTP_XOR_MULT_DOSStub_a62d {
  strings:
    $key_a62d = { f2 45 [2] 86 5d [2] c1 5f [2] 86 4e [2] c8 42 [2] c4 48 [2] d3 43 [2] c8 0d [2] f5 }

  condition:
    any of them
}