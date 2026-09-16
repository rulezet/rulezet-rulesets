rule TTP_XOR_MULT_DOSStub_e6c6 {
  strings:
    $key_e6c6 = { b2 ae [2] c6 b6 [2] 81 b4 [2] c6 a5 [2] 88 a9 [2] 84 a3 [2] 93 a8 [2] 88 e6 [2] b5 }

  condition:
    any of them
}