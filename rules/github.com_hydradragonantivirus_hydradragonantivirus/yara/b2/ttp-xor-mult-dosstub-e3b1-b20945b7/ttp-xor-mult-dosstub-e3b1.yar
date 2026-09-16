rule TTP_XOR_MULT_DOSStub_e3b1 {
  strings:
    $key_e3b1 = { b7 d9 [2] c3 c1 [2] 84 c3 [2] c3 d2 [2] 8d de [2] 81 d4 [2] 96 df [2] 8d 91 [2] b0 }

  condition:
    any of them
}