rule TTP_XOR_MULT_DOSStub_24b4 {
  strings:
    $key_24b4 = { 70 dc [2] 04 c4 [2] 43 c6 [2] 04 d7 [2] 4a db [2] 46 d1 [2] 51 da [2] 4a 94 [2] 77 }

  condition:
    any of them
}