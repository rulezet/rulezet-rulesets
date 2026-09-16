rule TTP_XOR_MULT_DOSStub_17c0 {
  strings:
    $key_17c0 = { 43 a8 [2] 37 b0 [2] 70 b2 [2] 37 a3 [2] 79 af [2] 75 a5 [2] 62 ae [2] 79 e0 [2] 44 }

  condition:
    any of them
}