rule TTP_XOR_MULT_DOSStub_4fab {
  strings:
    $key_4fab = { 1b c3 [2] 6f db [2] 28 d9 [2] 6f c8 [2] 21 c4 [2] 2d ce [2] 3a c5 [2] 21 8b [2] 1c }

  condition:
    any of them
}