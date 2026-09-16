rule TTP_XOR_MULT_DOSStub_f1d6 {
  strings:
    $key_f1d6 = { a5 be [2] d1 a6 [2] 96 a4 [2] d1 b5 [2] 9f b9 [2] 93 b3 [2] 84 b8 [2] 9f f6 [2] a2 }

  condition:
    any of them
}