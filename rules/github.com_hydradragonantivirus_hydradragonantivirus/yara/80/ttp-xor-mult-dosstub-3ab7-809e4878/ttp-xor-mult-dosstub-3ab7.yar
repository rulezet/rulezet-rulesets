rule TTP_XOR_MULT_DOSStub_3ab7 {
  strings:
    $key_3ab7 = { 6e df [2] 1a c7 [2] 5d c5 [2] 1a d4 [2] 54 d8 [2] 58 d2 [2] 4f d9 [2] 54 97 [2] 69 }

  condition:
    any of them
}