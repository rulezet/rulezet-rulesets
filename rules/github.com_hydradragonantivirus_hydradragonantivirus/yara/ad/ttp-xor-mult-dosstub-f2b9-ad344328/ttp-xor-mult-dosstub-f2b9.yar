rule TTP_XOR_MULT_DOSStub_f2b9 {
  strings:
    $key_f2b9 = { a6 d1 [2] d2 c9 [2] 95 cb [2] d2 da [2] 9c d6 [2] 90 dc [2] 87 d7 [2] 9c 99 [2] a1 }

  condition:
    any of them
}