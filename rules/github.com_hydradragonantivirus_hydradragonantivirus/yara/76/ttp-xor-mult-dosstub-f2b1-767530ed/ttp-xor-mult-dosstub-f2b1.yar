rule TTP_XOR_MULT_DOSStub_f2b1 {
  strings:
    $key_f2b1 = { a6 d9 [2] d2 c1 [2] 95 c3 [2] d2 d2 [2] 9c de [2] 90 d4 [2] 87 df [2] 9c 91 [2] a1 }

  condition:
    any of them
}