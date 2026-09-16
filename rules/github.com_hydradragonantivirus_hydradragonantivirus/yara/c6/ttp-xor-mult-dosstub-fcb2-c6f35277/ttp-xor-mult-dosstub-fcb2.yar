rule TTP_XOR_MULT_DOSStub_fcb2 {
  strings:
    $key_fcb2 = { a8 da [2] dc c2 [2] 9b c0 [2] dc d1 [2] 92 dd [2] 9e d7 [2] 89 dc [2] 92 92 [2] af }

  condition:
    any of them
}