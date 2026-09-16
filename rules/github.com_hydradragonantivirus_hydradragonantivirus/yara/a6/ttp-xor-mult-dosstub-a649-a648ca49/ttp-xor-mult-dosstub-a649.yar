rule TTP_XOR_MULT_DOSStub_a649 {
  strings:
    $key_a649 = { f2 21 [2] 86 39 [2] c1 3b [2] 86 2a [2] c8 26 [2] c4 2c [2] d3 27 [2] c8 69 [2] f5 }

  condition:
    any of them
}