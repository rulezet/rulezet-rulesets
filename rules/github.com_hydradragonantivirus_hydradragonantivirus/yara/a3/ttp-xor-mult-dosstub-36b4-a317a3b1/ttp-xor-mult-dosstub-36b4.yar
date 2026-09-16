rule TTP_XOR_MULT_DOSStub_36b4 {
  strings:
    $key_36b4 = { 62 dc [2] 16 c4 [2] 51 c6 [2] 16 d7 [2] 58 db [2] 54 d1 [2] 43 da [2] 58 94 [2] 65 }

  condition:
    any of them
}