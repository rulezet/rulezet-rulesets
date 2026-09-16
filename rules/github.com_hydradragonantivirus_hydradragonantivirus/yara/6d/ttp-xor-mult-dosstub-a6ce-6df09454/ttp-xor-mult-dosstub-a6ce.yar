rule TTP_XOR_MULT_DOSStub_a6ce {
  strings:
    $key_a6ce = { f2 a6 [2] 86 be [2] c1 bc [2] 86 ad [2] c8 a1 [2] c4 ab [2] d3 a0 [2] c8 ee [2] f5 }

  condition:
    any of them
}