rule TTP_XOR_MULT_DOSStub_e284 {
  strings:
    $key_e284 = { b6 ec [2] c2 f4 [2] 85 f6 [2] c2 e7 [2] 8c eb [2] 80 e1 [2] 97 ea [2] 8c a4 [2] b1 }

  condition:
    any of them
}