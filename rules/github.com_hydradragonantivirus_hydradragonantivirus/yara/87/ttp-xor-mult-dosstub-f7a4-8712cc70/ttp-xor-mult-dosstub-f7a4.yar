rule TTP_XOR_MULT_DOSStub_f7a4 {
  strings:
    $key_f7a4 = { a3 cc [2] d7 d4 [2] 90 d6 [2] d7 c7 [2] 99 cb [2] 95 c1 [2] 82 ca [2] 99 84 [2] a4 }

  condition:
    any of them
}