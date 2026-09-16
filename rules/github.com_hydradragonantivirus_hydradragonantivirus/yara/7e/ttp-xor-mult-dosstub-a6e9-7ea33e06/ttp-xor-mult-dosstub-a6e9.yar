rule TTP_XOR_MULT_DOSStub_a6e9 {
  strings:
    $key_a6e9 = { f2 81 [2] 86 99 [2] c1 9b [2] 86 8a [2] c8 86 [2] c4 8c [2] d3 87 [2] c8 c9 [2] f5 }

  condition:
    any of them
}