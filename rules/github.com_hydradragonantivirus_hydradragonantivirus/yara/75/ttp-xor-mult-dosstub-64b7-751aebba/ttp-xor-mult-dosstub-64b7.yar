rule TTP_XOR_MULT_DOSStub_64b7 {
  strings:
    $key_64b7 = { 30 df [2] 44 c7 [2] 03 c5 [2] 44 d4 [2] 0a d8 [2] 06 d2 [2] 11 d9 [2] 0a 97 [2] 37 }

  condition:
    any of them
}