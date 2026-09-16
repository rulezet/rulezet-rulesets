rule TTP_XOR_MULT_DOSStub_45b4 {
  strings:
    $key_45b4 = { 11 dc [2] 65 c4 [2] 22 c6 [2] 65 d7 [2] 2b db [2] 27 d1 [2] 30 da [2] 2b 94 [2] 16 }

  condition:
    any of them
}