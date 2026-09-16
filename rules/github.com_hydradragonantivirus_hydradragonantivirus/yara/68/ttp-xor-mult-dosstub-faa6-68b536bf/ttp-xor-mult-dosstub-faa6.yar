rule TTP_XOR_MULT_DOSStub_faa6 {
  strings:
    $key_faa6 = { ae ce [2] da d6 [2] 9d d4 [2] da c5 [2] 94 c9 [2] 98 c3 [2] 8f c8 [2] 94 86 [2] a9 }

  condition:
    any of them
}