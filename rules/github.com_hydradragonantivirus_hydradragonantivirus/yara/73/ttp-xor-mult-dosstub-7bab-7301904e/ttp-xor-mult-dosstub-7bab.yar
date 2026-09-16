rule TTP_XOR_MULT_DOSStub_7bab {
  strings:
    $key_7bab = { 2f c3 [2] 5b db [2] 1c d9 [2] 5b c8 [2] 15 c4 [2] 19 ce [2] 0e c5 [2] 15 8b [2] 28 }

  condition:
    any of them
}