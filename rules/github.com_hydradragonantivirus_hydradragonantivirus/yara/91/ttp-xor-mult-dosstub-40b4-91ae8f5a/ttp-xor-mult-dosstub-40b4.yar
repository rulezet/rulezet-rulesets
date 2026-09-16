rule TTP_XOR_MULT_DOSStub_40b4 {
  strings:
    $key_40b4 = { 14 dc [2] 60 c4 [2] 27 c6 [2] 60 d7 [2] 2e db [2] 22 d1 [2] 35 da [2] 2e 94 [2] 13 }

  condition:
    any of them
}