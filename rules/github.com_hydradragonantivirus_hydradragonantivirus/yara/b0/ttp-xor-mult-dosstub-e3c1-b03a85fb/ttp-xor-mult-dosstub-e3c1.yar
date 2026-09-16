rule TTP_XOR_MULT_DOSStub_e3c1 {
  strings:
    $key_e3c1 = { b7 a9 [2] c3 b1 [2] 84 b3 [2] c3 a2 [2] 8d ae [2] 81 a4 [2] 96 af [2] 8d e1 [2] b0 }

  condition:
    any of them
}