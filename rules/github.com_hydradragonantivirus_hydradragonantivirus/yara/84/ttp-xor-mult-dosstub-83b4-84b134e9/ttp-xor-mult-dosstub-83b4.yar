rule TTP_XOR_MULT_DOSStub_83b4 {
  strings:
    $key_83b4 = { d7 dc [2] a3 c4 [2] e4 c6 [2] a3 d7 [2] ed db [2] e1 d1 [2] f6 da [2] ed 94 [2] d0 }

  condition:
    any of them
}