rule TTP_XOR_MULT_DOSStub_a6aa {
  strings:
    $key_a6aa = { f2 c2 [2] 86 da [2] c1 d8 [2] 86 c9 [2] c8 c5 [2] c4 cf [2] d3 c4 [2] c8 8a [2] f5 }

  condition:
    any of them
}