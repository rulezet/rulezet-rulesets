rule TTP_XOR_MULT_DOSStub_f2b7 {
  strings:
    $key_f2b7 = { a6 df [2] d2 c7 [2] 95 c5 [2] d2 d4 [2] 9c d8 [2] 90 d2 [2] 87 d9 [2] 9c 97 [2] a1 }

  condition:
    any of them
}