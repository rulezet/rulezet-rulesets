rule TTP_XOR_MULT_DOSStub_1aa6 {
  strings:
    $key_1aa6 = { 4e ce [2] 3a d6 [2] 7d d4 [2] 3a c5 [2] 74 c9 [2] 78 c3 [2] 6f c8 [2] 74 86 [2] 49 }

  condition:
    any of them
}