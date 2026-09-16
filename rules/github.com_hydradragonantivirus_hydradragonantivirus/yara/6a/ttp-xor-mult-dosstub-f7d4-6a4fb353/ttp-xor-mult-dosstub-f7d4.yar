rule TTP_XOR_MULT_DOSStub_f7d4 {
  strings:
    $key_f7d4 = { a3 bc [2] d7 a4 [2] 90 a6 [2] d7 b7 [2] 99 bb [2] 95 b1 [2] 82 ba [2] 99 f4 [2] a4 }

  condition:
    any of them
}