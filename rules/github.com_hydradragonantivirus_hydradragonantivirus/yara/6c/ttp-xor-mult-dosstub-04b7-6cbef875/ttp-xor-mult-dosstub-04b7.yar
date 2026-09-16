rule TTP_XOR_MULT_DOSStub_04b7 {
  strings:
    $key_04b7 = { 50 df [2] 24 c7 [2] 63 c5 [2] 24 d4 [2] 6a d8 [2] 66 d2 [2] 71 d9 [2] 6a 97 [2] 57 }

  condition:
    any of them
}