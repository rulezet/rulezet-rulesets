rule TTP_XOR_MULT_DOSStub_fcad {
  strings:
    $key_fcad = { a8 c5 [2] dc dd [2] 9b df [2] dc ce [2] 92 c2 [2] 9e c8 [2] 89 c3 [2] 92 8d [2] af }

  condition:
    any of them
}