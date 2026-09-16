rule TTP_XOR_MULT_DOSStub_a1aa {
  strings:
    $key_a1aa = { f5 c2 [2] 81 da [2] c6 d8 [2] 81 c9 [2] cf c5 [2] c3 cf [2] d4 c4 [2] cf 8a [2] f2 }

  condition:
    any of them
}