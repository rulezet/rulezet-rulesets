rule TTP_XOR_MULT_DOSStub_a2a7 {
  strings:
    $key_a2a7 = { f6 cf [2] 82 d7 [2] c5 d5 [2] 82 c4 [2] cc c8 [2] c0 c2 [2] d7 c9 [2] cc 87 [2] f1 }

  condition:
    any of them
}