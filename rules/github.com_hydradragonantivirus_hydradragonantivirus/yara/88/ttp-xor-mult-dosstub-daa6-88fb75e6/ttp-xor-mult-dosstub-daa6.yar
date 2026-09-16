rule TTP_XOR_MULT_DOSStub_daa6 {
  strings:
    $key_daa6 = { 8e ce [2] fa d6 [2] bd d4 [2] fa c5 [2] b4 c9 [2] b8 c3 [2] af c8 [2] b4 86 [2] 89 }

  condition:
    any of them
}