rule TTP_XOR_MULT_DOSStub_1fab {
  strings:
    $key_1fab = { 4b c3 [2] 3f db [2] 78 d9 [2] 3f c8 [2] 71 c4 [2] 7d ce [2] 6a c5 [2] 71 8b [2] 4c }

  condition:
    any of them
}