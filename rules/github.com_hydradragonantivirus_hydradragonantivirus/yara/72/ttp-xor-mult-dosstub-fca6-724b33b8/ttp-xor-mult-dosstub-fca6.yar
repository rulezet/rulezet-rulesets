rule TTP_XOR_MULT_DOSStub_fca6 {
  strings:
    $key_fca6 = { a8 ce [2] dc d6 [2] 9b d4 [2] dc c5 [2] 92 c9 [2] 9e c3 [2] 89 c8 [2] 92 86 [2] af }

  condition:
    any of them
}