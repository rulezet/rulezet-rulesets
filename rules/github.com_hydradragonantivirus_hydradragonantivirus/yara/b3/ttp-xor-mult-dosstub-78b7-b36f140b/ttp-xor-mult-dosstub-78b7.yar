rule TTP_XOR_MULT_DOSStub_78b7 {
  strings:
    $key_78b7 = { 2c df [2] 58 c7 [2] 1f c5 [2] 58 d4 [2] 16 d8 [2] 1a d2 [2] 0d d9 [2] 16 97 [2] 2b }

  condition:
    any of them
}