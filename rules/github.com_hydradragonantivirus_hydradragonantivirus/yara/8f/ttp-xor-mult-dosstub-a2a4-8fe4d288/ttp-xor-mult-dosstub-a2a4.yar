rule TTP_XOR_MULT_DOSStub_a2a4 {
  strings:
    $key_a2a4 = { f6 cc [2] 82 d4 [2] c5 d6 [2] 82 c7 [2] cc cb [2] c0 c1 [2] d7 ca [2] cc 84 [2] f1 }

  condition:
    any of them
}