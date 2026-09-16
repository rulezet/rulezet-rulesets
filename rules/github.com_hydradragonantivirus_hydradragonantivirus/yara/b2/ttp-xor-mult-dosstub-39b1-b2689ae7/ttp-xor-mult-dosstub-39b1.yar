rule TTP_XOR_MULT_DOSStub_39b1 {
  strings:
    $key_39b1 = { 6d d9 [2] 19 c1 [2] 5e c3 [2] 19 d2 [2] 57 de [2] 5b d4 [2] 4c df [2] 57 91 [2] 6a }

  condition:
    any of them
}