rule TTP_XOR_MULT_DOSStub_7fab {
  strings:
    $key_7fab = { 2b c3 [2] 5f db [2] 18 d9 [2] 5f c8 [2] 11 c4 [2] 1d ce [2] 0a c5 [2] 11 8b [2] 2c }

  condition:
    any of them
}