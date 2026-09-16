rule TTP_XOR_MULT_DOSStub_e7c7 {
  strings:
    $key_e7c7 = { b3 af [2] c7 b7 [2] 80 b5 [2] c7 a4 [2] 89 a8 [2] 85 a2 [2] 92 a9 [2] 89 e7 [2] b4 }

  condition:
    any of them
}