rule TTP_XOR_MULT_DOSStub_f5d6 {
  strings:
    $key_f5d6 = { a1 be [2] d5 a6 [2] 92 a4 [2] d5 b5 [2] 9b b9 [2] 97 b3 [2] 80 b8 [2] 9b f6 [2] a6 }

  condition:
    any of them
}