rule TTP_XOR_MULT_DOSStub_a614 {
  strings:
    $key_a614 = { f2 7c [2] 86 64 [2] c1 66 [2] 86 77 [2] c8 7b [2] c4 71 [2] d3 7a [2] c8 34 [2] f5 }

  condition:
    any of them
}