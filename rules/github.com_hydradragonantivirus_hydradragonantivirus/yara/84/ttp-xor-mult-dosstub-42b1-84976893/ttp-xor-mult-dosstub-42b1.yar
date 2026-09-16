rule TTP_XOR_MULT_DOSStub_42b1 {
  strings:
    $key_42b1 = { 16 d9 [2] 62 c1 [2] 25 c3 [2] 62 d2 [2] 2c de [2] 20 d4 [2] 37 df [2] 2c 91 [2] 11 }

  condition:
    any of them
}