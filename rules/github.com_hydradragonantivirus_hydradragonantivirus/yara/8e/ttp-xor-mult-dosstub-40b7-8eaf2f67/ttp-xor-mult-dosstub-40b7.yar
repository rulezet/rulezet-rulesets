rule TTP_XOR_MULT_DOSStub_40b7 {
  strings:
    $key_40b7 = { 14 df [2] 60 c7 [2] 27 c5 [2] 60 d4 [2] 2e d8 [2] 22 d2 [2] 35 d9 [2] 2e 97 [2] 13 }

  condition:
    any of them
}