rule TTP_XOR_MULT_DOSStub_36c1 {
  strings:
    $key_36c1 = { 62 a9 [2] 16 b1 [2] 51 b3 [2] 16 a2 [2] 58 ae [2] 54 a4 [2] 43 af [2] 58 e1 [2] 65 }

  condition:
    any of them
}