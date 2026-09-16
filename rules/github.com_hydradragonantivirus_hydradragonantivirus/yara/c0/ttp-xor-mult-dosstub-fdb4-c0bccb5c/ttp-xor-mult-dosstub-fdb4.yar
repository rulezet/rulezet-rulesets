rule TTP_XOR_MULT_DOSStub_fdb4 {
  strings:
    $key_fdb4 = { a9 dc [2] dd c4 [2] 9a c6 [2] dd d7 [2] 93 db [2] 9f d1 [2] 88 da [2] 93 94 [2] ae }

  condition:
    any of them
}