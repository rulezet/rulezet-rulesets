rule TTP_XOR_MULT_DOSStub_fca8 {
  strings:
    $key_fca8 = { a8 c0 [2] dc d8 [2] 9b da [2] dc cb [2] 92 c7 [2] 9e cd [2] 89 c6 [2] 92 88 [2] af }

  condition:
    any of them
}