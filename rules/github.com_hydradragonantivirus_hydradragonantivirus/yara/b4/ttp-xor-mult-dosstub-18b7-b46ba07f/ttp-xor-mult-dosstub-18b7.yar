rule TTP_XOR_MULT_DOSStub_18b7 {
  strings:
    $key_18b7 = { 4c df [2] 38 c7 [2] 7f c5 [2] 38 d4 [2] 76 d8 [2] 7a d2 [2] 6d d9 [2] 76 97 [2] 4b }

  condition:
    any of them
}