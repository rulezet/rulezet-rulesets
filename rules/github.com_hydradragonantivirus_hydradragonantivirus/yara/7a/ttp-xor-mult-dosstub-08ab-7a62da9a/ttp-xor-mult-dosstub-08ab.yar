rule TTP_XOR_MULT_DOSStub_08ab {
  strings:
    $key_08ab = { 5c c3 [2] 28 db [2] 6f d9 [2] 28 c8 [2] 66 c4 [2] 6a ce [2] 7d c5 [2] 66 8b [2] 5b }

  condition:
    any of them
}