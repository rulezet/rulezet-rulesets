rule TTP_XOR_MULT_DOSStub_4da6 {
  strings:
    $key_4da6 = { 19 ce [2] 6d d6 [2] 2a d4 [2] 6d c5 [2] 23 c9 [2] 2f c3 [2] 38 c8 [2] 23 86 [2] 1e }

  condition:
    any of them
}