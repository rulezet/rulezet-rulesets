rule TTP_XOR_MULT_DOSStub_15b4 {
  strings:
    $key_15b4 = { 41 dc [2] 35 c4 [2] 72 c6 [2] 35 d7 [2] 7b db [2] 77 d1 [2] 60 da [2] 7b 94 [2] 46 }

  condition:
    any of them
}