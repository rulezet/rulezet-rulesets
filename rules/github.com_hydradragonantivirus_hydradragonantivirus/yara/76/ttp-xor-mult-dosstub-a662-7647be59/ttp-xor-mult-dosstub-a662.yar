rule TTP_XOR_MULT_DOSStub_a662 {
  strings:
    $key_a662 = { f2 0a [2] 86 12 [2] c1 10 [2] 86 01 [2] c8 0d [2] c4 07 [2] d3 0c [2] c8 42 [2] f5 }

  condition:
    any of them
}