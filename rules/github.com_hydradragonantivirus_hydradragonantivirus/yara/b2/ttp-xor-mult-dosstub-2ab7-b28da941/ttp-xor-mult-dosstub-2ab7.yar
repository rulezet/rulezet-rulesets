rule TTP_XOR_MULT_DOSStub_2ab7 {
  strings:
    $key_2ab7 = { 7e df [2] 0a c7 [2] 4d c5 [2] 0a d4 [2] 44 d8 [2] 48 d2 [2] 5f d9 [2] 44 97 [2] 79 }

  condition:
    any of them
}