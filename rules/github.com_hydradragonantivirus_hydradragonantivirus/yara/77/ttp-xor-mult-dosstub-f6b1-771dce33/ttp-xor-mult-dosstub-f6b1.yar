rule TTP_XOR_MULT_DOSStub_f6b1 {
  strings:
    $key_f6b1 = { a2 d9 [2] d6 c1 [2] 91 c3 [2] d6 d2 [2] 98 de [2] 94 d4 [2] 83 df [2] 98 91 [2] a5 }

  condition:
    any of them
}