rule TTP_XOR_MULT_DOSStub_e7c0 {
  strings:
    $key_e7c0 = { b3 a8 [2] c7 b0 [2] 80 b2 [2] c7 a3 [2] 89 af [2] 85 a5 [2] 92 ae [2] 89 e0 [2] b4 }

  condition:
    any of them
}