rule TTP_XOR_MULT_DOSStub_56b1 {
  strings:
    $key_56b1 = { 02 d9 [2] 76 c1 [2] 31 c3 [2] 76 d2 [2] 38 de [2] 34 d4 [2] 23 df [2] 38 91 [2] 05 }

  condition:
    any of them
}