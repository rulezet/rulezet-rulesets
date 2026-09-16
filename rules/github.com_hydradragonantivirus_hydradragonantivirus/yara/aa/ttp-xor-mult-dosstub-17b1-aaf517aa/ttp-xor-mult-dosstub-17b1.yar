rule TTP_XOR_MULT_DOSStub_17b1 {
  strings:
    $key_17b1 = { 43 d9 [2] 37 c1 [2] 70 c3 [2] 37 d2 [2] 79 de [2] 75 d4 [2] 62 df [2] 79 91 [2] 44 }

  condition:
    any of them
}