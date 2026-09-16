rule TTP_XOR_MULT_DOSStub_e6c0 {
  strings:
    $key_e6c0 = { b2 a8 [2] c6 b0 [2] 81 b2 [2] c6 a3 [2] 88 af [2] 84 a5 [2] 93 ae [2] 88 e0 [2] b5 }

  condition:
    any of them
}