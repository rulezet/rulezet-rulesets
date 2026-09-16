rule TTP_XOR_MULT_DOSStub_fcb3 {
  strings:
    $key_fcb3 = { a8 db [2] dc c3 [2] 9b c1 [2] dc d0 [2] 92 dc [2] 9e d6 [2] 89 dd [2] 92 93 [2] af }

  condition:
    any of them
}