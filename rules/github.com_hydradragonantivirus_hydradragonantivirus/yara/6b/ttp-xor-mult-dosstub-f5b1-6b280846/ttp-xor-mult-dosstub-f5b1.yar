rule TTP_XOR_MULT_DOSStub_f5b1 {
  strings:
    $key_f5b1 = { a1 d9 [2] d5 c1 [2] 92 c3 [2] d5 d2 [2] 9b de [2] 97 d4 [2] 80 df [2] 9b 91 [2] a6 }

  condition:
    any of them
}