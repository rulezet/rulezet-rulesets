rule TTP_XOR_MULT_DOSStub_f7c8 {
  strings:
    $key_f7c8 = { a3 a0 [2] d7 b8 [2] 90 ba [2] d7 ab [2] 99 a7 [2] 95 ad [2] 82 a6 [2] 99 e8 [2] a4 }

  condition:
    any of them
}