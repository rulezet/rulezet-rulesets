rule TTP_XOR_MULT_DOSStub_f1c6 {
  strings:
    $key_f1c6 = { a5 ae [2] d1 b6 [2] 96 b4 [2] d1 a5 [2] 9f a9 [2] 93 a3 [2] 84 a8 [2] 9f e6 [2] a2 }

  condition:
    any of them
}