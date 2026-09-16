rule TTP_XOR_MULT_DOSStub_41b4 {
  strings:
    $key_41b4 = { 15 dc [2] 61 c4 [2] 26 c6 [2] 61 d7 [2] 2f db [2] 23 d1 [2] 34 da [2] 2f 94 [2] 12 }

  condition:
    any of them
}