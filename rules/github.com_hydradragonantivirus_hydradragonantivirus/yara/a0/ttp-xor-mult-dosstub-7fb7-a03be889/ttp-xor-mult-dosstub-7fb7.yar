rule TTP_XOR_MULT_DOSStub_7fb7 {
  strings:
    $key_7fb7 = { 2b df [2] 5f c7 [2] 18 c5 [2] 5f d4 [2] 11 d8 [2] 1d d2 [2] 0a d9 [2] 11 97 [2] 2c }

  condition:
    any of them
}