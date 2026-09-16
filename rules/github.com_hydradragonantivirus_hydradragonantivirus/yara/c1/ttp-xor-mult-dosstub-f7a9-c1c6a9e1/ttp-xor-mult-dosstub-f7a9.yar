rule TTP_XOR_MULT_DOSStub_f7a9 {
  strings:
    $key_f7a9 = { a3 c1 [2] d7 d9 [2] 90 db [2] d7 ca [2] 99 c6 [2] 95 cc [2] 82 c7 [2] 99 89 [2] a4 }

  condition:
    any of them
}