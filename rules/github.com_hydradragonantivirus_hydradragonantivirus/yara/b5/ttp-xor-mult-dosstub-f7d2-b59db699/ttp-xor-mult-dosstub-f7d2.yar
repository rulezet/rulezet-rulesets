rule TTP_XOR_MULT_DOSStub_f7d2 {
  strings:
    $key_f7d2 = { a3 ba [2] d7 a2 [2] 90 a0 [2] d7 b1 [2] 99 bd [2] 95 b7 [2] 82 bc [2] 99 f2 [2] a4 }

  condition:
    any of them
}