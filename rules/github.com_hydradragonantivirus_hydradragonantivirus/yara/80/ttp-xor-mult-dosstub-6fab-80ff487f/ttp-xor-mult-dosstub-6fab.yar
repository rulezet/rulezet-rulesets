rule TTP_XOR_MULT_DOSStub_6fab {
  strings:
    $key_6fab = { 3b c3 [2] 4f db [2] 08 d9 [2] 4f c8 [2] 01 c4 [2] 0d ce [2] 1a c5 [2] 01 8b [2] 3c }

  condition:
    any of them
}