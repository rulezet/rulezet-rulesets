rule TTP_XOR_MULT_DOSStub_f7b3 {
  strings:
    $key_f7b3 = { a3 db [2] d7 c3 [2] 90 c1 [2] d7 d0 [2] 99 dc [2] 95 d6 [2] 82 dd [2] 99 93 [2] a4 }

  condition:
    any of them
}