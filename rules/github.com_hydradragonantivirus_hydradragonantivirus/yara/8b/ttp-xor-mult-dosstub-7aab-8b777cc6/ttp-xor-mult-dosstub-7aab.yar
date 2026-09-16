rule TTP_XOR_MULT_DOSStub_7aab {
  strings:
    $key_7aab = { 2e c3 [2] 5a db [2] 1d d9 [2] 5a c8 [2] 14 c4 [2] 18 ce [2] 0f c5 [2] 14 8b [2] 29 }

  condition:
    any of them
}