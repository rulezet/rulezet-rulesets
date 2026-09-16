rule TTP_XOR_MULT_DOSStub_f0b7 {
  strings:
    $key_f0b7 = { a4 df [2] d0 c7 [2] 97 c5 [2] d0 d4 [2] 9e d8 [2] 92 d2 [2] 85 d9 [2] 9e 97 [2] a3 }

  condition:
    any of them
}