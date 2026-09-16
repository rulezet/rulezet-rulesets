rule TTP_XOR_MULT_DOSStub_46b4 {
  strings:
    $key_46b4 = { 12 dc [2] 66 c4 [2] 21 c6 [2] 66 d7 [2] 28 db [2] 24 d1 [2] 33 da [2] 28 94 [2] 15 }

  condition:
    any of them
}