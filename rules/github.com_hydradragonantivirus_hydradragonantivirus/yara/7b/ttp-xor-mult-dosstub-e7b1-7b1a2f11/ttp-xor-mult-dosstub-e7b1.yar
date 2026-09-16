rule TTP_XOR_MULT_DOSStub_e7b1 {
  strings:
    $key_e7b1 = { b3 d9 [2] c7 c1 [2] 80 c3 [2] c7 d2 [2] 89 de [2] 85 d4 [2] 92 df [2] 89 91 [2] b4 }

  condition:
    any of them
}