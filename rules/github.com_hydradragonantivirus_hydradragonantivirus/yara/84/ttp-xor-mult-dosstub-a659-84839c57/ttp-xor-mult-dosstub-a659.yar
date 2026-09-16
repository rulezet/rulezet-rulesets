rule TTP_XOR_MULT_DOSStub_a659 {
  strings:
    $key_a659 = { f2 31 [2] 86 29 [2] c1 2b [2] 86 3a [2] c8 36 [2] c4 3c [2] d3 37 [2] c8 79 [2] f5 }

  condition:
    any of them
}