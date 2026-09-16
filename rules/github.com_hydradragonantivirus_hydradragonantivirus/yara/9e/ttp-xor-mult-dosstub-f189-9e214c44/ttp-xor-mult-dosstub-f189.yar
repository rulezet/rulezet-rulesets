rule TTP_XOR_MULT_DOSStub_f189 {
  strings:
    $key_f189 = { a5 e1 [2] d1 f9 [2] 96 fb [2] d1 ea [2] 9f e6 [2] 93 ec [2] 84 e7 [2] 9f a9 [2] a2 }

  condition:
    any of them
}