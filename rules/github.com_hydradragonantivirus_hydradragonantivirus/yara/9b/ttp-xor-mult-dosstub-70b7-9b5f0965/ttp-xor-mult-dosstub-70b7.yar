rule TTP_XOR_MULT_DOSStub_70b7 {
  strings:
    $key_70b7 = { 24 df [2] 50 c7 [2] 17 c5 [2] 50 d4 [2] 1e d8 [2] 12 d2 [2] 05 d9 [2] 1e 97 [2] 23 }

  condition:
    any of them
}