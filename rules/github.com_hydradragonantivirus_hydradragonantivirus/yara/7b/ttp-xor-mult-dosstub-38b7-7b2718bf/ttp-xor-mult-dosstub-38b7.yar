rule TTP_XOR_MULT_DOSStub_38b7 {
  strings:
    $key_38b7 = { 6c df [2] 18 c7 [2] 5f c5 [2] 18 d4 [2] 56 d8 [2] 5a d2 [2] 4d d9 [2] 56 97 [2] 6b }

  condition:
    any of them
}