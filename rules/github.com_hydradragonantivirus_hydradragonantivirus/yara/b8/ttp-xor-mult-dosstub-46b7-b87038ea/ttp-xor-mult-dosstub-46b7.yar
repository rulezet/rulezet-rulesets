rule TTP_XOR_MULT_DOSStub_46b7 {
  strings:
    $key_46b7 = { 12 df [2] 66 c7 [2] 21 c5 [2] 66 d4 [2] 28 d8 [2] 24 d2 [2] 33 d9 [2] 28 97 [2] 15 }

  condition:
    any of them
}