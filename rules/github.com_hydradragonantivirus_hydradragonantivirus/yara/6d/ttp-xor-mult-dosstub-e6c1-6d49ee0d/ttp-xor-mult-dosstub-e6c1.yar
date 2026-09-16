rule TTP_XOR_MULT_DOSStub_e6c1 {
  strings:
    $key_e6c1 = { b2 a9 [2] c6 b1 [2] 81 b3 [2] c6 a2 [2] 88 ae [2] 84 a4 [2] 93 af [2] 88 e1 [2] b5 }

  condition:
    any of them
}