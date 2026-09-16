rule TTP_XOR_MULT_DOSStub_a612 {
  strings:
    $key_a612 = { f2 7a [2] 86 62 [2] c1 60 [2] 86 71 [2] c8 7d [2] c4 77 [2] d3 7c [2] c8 32 [2] f5 }

  condition:
    any of them
}