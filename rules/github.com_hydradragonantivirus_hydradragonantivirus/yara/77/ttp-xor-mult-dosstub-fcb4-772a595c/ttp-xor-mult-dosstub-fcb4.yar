rule TTP_XOR_MULT_DOSStub_fcb4 {
  strings:
    $key_fcb4 = { a8 dc [2] dc c4 [2] 9b c6 [2] dc d7 [2] 92 db [2] 9e d1 [2] 89 da [2] 92 94 [2] af }

  condition:
    any of them
}