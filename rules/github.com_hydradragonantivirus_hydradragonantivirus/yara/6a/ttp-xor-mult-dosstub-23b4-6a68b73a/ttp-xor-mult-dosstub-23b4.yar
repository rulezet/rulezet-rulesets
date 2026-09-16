rule TTP_XOR_MULT_DOSStub_23b4 {
  strings:
    $key_23b4 = { 77 dc [2] 03 c4 [2] 44 c6 [2] 03 d7 [2] 4d db [2] 41 d1 [2] 56 da [2] 4d 94 [2] 70 }

  condition:
    any of them
}