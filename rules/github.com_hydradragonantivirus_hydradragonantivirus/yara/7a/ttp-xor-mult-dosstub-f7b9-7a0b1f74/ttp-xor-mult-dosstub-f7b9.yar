rule TTP_XOR_MULT_DOSStub_f7b9 {
  strings:
    $key_f7b9 = { a3 d1 [2] d7 c9 [2] 90 cb [2] d7 da [2] 99 d6 [2] 95 dc [2] 82 d7 [2] 99 99 [2] a4 }

  condition:
    any of them
}