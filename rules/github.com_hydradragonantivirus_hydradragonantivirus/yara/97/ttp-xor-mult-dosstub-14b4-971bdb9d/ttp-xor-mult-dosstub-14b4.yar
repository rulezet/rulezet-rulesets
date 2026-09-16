rule TTP_XOR_MULT_DOSStub_14b4 {
  strings:
    $key_14b4 = { 40 dc [2] 34 c4 [2] 73 c6 [2] 34 d7 [2] 7a db [2] 76 d1 [2] 61 da [2] 7a 94 [2] 47 }

  condition:
    any of them
}