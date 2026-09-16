rule TTP_XOR_MULT_DOSStub_f096 {
  strings:
    $key_f096 = { a4 fe [2] d0 e6 [2] 97 e4 [2] d0 f5 [2] 9e f9 [2] 92 f3 [2] 85 f8 [2] 9e b6 [2] a3 }

  condition:
    any of them
}