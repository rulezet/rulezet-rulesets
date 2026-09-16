rule TTP_XOR_MULT_DOSStub_e7c6 {
  strings:
    $key_e7c6 = { b3 ae [2] c7 b6 [2] 80 b4 [2] c7 a5 [2] 89 a9 [2] 85 a3 [2] 92 a8 [2] 89 e6 [2] b4 }

  condition:
    any of them
}