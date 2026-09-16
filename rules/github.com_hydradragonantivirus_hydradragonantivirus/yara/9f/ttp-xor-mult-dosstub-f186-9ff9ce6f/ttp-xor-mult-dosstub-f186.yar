rule TTP_XOR_MULT_DOSStub_f186 {
  strings:
    $key_f186 = { a5 ee [2] d1 f6 [2] 96 f4 [2] d1 e5 [2] 9f e9 [2] 93 e3 [2] 84 e8 [2] 9f a6 [2] a2 }

  condition:
    any of them
}