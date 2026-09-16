rule TTP_XOR_MULT_DOSStub_25b4 {
  strings:
    $key_25b4 = { 71 dc [2] 05 c4 [2] 42 c6 [2] 05 d7 [2] 4b db [2] 47 d1 [2] 50 da [2] 4b 94 [2] 76 }

  condition:
    any of them
}