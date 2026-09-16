rule TTP_XOR_MULT_DOSStub_e2b1 {
  strings:
    $key_e2b1 = { b6 d9 [2] c2 c1 [2] 85 c3 [2] c2 d2 [2] 8c de [2] 80 d4 [2] 97 df [2] 8c 91 [2] b1 }

  condition:
    any of them
}