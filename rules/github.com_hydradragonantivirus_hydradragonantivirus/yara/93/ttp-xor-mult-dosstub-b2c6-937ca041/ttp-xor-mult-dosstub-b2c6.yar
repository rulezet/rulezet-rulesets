rule TTP_XOR_MULT_DOSStub_b2c6 {
  strings:
    $key_b2c6 = { e6 ae [2] 92 b6 [2] d5 b4 [2] 92 a5 [2] dc a9 [2] d0 a3 [2] c7 a8 [2] dc e6 [2] e1 }

  condition:
    any of them
}