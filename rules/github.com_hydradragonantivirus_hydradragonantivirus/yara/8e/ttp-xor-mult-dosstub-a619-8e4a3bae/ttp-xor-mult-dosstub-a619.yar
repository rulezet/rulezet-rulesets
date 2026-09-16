rule TTP_XOR_MULT_DOSStub_a619 {
  strings:
    $key_a619 = { f2 71 [2] 86 69 [2] c1 6b [2] 86 7a [2] c8 76 [2] c4 7c [2] d3 77 [2] c8 39 [2] f5 }

  condition:
    any of them
}