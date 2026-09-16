rule TTP_XOR_MULT_DOSStub_a2b1 {
  strings:
    $key_a2b1 = { f6 d9 [2] 82 c1 [2] c5 c3 [2] 82 d2 [2] cc de [2] c0 d4 [2] d7 df [2] cc 91 [2] f1 }

  condition:
    any of them
}