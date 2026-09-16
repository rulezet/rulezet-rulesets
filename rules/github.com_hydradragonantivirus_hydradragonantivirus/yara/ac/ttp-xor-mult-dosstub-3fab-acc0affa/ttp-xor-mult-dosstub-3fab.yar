rule TTP_XOR_MULT_DOSStub_3fab {
  strings:
    $key_3fab = { 6b c3 [2] 1f db [2] 58 d9 [2] 1f c8 [2] 51 c4 [2] 5d ce [2] 4a c5 [2] 51 8b [2] 6c }

  condition:
    any of them
}