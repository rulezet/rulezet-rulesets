rule TTP_XOR_MULT_DOSStub_03b1 {
  strings:
    $key_03b1 = { 57 d9 [2] 23 c1 [2] 64 c3 [2] 23 d2 [2] 6d de [2] 61 d4 [2] 76 df [2] 6d 91 [2] 50 }

  condition:
    any of them
}