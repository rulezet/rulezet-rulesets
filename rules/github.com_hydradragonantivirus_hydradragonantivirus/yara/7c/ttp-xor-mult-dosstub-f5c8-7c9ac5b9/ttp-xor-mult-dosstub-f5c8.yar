rule TTP_XOR_MULT_DOSStub_f5c8 {
  strings:
    $key_f5c8 = { a1 a0 [2] d5 b8 [2] 92 ba [2] d5 ab [2] 9b a7 [2] 97 ad [2] 80 a6 [2] 9b e8 [2] a6 }

  condition:
    any of them
}