rule TTP_XOR_MULT_DOSStub_a2a6 {
  strings:
    $key_a2a6 = { f6 ce [2] 82 d6 [2] c5 d4 [2] 82 c5 [2] cc c9 [2] c0 c3 [2] d7 c8 [2] cc 86 [2] f1 }

  condition:
    any of them
}