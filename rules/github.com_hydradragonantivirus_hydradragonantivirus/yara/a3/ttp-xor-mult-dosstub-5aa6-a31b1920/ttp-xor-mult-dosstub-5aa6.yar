rule TTP_XOR_MULT_DOSStub_5aa6 {
  strings:
    $key_5aa6 = { 0e ce [2] 7a d6 [2] 3d d4 [2] 7a c5 [2] 34 c9 [2] 38 c3 [2] 2f c8 [2] 34 86 [2] 09 }

  condition:
    any of them
}