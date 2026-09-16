rule TTP_XOR_MULT_DOSStub_c8a6 {
  strings:
    $key_c8a6 = { 9c ce [2] e8 d6 [2] af d4 [2] e8 c5 [2] a6 c9 [2] aa c3 [2] bd c8 [2] a6 86 [2] 9b }

  condition:
    any of them
}