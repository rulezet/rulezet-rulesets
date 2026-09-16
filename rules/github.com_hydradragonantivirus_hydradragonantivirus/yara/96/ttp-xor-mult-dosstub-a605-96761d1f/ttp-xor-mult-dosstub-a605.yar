rule TTP_XOR_MULT_DOSStub_a605 {
  strings:
    $key_a605 = { f2 6d [2] 86 75 [2] c1 77 [2] 86 66 [2] c8 6a [2] c4 60 [2] d3 6b [2] c8 25 [2] f5 }

  condition:
    any of them
}