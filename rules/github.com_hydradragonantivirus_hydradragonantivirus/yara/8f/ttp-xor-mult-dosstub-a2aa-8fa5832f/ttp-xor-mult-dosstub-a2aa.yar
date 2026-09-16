rule TTP_XOR_MULT_DOSStub_a2aa {
  strings:
    $key_a2aa = { f6 c2 [2] 82 da [2] c5 d8 [2] 82 c9 [2] cc c5 [2] c0 cf [2] d7 c4 [2] cc 8a [2] f1 }

  condition:
    any of them
}