rule TTP_XOR_MULT_DOSStub_f7b4 {
  strings:
    $key_f7b4 = { a3 dc [2] d7 c4 [2] 90 c6 [2] d7 d7 [2] 99 db [2] 95 d1 [2] 82 da [2] 99 94 [2] a4 }

  condition:
    any of them
}