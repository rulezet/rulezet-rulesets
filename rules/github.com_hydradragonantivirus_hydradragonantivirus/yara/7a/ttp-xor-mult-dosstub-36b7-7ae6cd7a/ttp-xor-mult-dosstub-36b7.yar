rule TTP_XOR_MULT_DOSStub_36b7 {
  strings:
    $key_36b7 = { 62 df [2] 16 c7 [2] 51 c5 [2] 16 d4 [2] 58 d8 [2] 54 d2 [2] 43 d9 [2] 58 97 [2] 65 }

  condition:
    any of them
}