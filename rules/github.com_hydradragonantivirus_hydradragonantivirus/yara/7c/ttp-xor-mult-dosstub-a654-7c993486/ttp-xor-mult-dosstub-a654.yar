rule TTP_XOR_MULT_DOSStub_a654 {
  strings:
    $key_a654 = { f2 3c [2] 86 24 [2] c1 26 [2] 86 37 [2] c8 3b [2] c4 31 [2] d3 3a [2] c8 74 [2] f5 }

  condition:
    any of them
}