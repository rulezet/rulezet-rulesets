rule TTP_XOR_MULT_DOSStub_20b7 {
  strings:
    $key_20b7 = { 74 df [2] 00 c7 [2] 47 c5 [2] 00 d4 [2] 4e d8 [2] 42 d2 [2] 55 d9 [2] 4e 97 [2] 73 }

  condition:
    any of them
}