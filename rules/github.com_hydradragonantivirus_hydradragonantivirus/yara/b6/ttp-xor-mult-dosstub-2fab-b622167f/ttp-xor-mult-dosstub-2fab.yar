rule TTP_XOR_MULT_DOSStub_2fab {
  strings:
    $key_2fab = { 7b c3 [2] 0f db [2] 48 d9 [2] 0f c8 [2] 41 c4 [2] 4d ce [2] 5a c5 [2] 41 8b [2] 7c }

  condition:
    any of them
}