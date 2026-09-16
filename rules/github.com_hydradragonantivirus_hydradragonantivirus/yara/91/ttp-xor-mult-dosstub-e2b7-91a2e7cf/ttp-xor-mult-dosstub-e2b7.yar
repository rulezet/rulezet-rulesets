rule TTP_XOR_MULT_DOSStub_e2b7 {
  strings:
    $key_e2b7 = { b6 df [2] c2 c7 [2] 85 c5 [2] c2 d4 [2] 8c d8 [2] 80 d2 [2] 97 d9 [2] 8c 97 [2] b1 }

  condition:
    any of them
}