rule TTP_XOR_MULT_DOSStub_f1c8 {
  strings:
    $key_f1c8 = { a5 a0 [2] d1 b8 [2] 96 ba [2] d1 ab [2] 9f a7 [2] 93 ad [2] 84 a6 [2] 9f e8 [2] a2 }

  condition:
    any of them
}