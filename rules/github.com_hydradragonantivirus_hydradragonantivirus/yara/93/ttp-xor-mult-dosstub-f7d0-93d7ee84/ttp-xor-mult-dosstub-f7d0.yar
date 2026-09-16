rule TTP_XOR_MULT_DOSStub_f7d0 {
  strings:
    $key_f7d0 = { a3 b8 [2] d7 a0 [2] 90 a2 [2] d7 b3 [2] 99 bf [2] 95 b5 [2] 82 be [2] 99 f0 [2] a4 }

  condition:
    any of them
}