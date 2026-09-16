rule TTP_XOR_MULT_DOSStub_1aab {
  strings:
    $key_1aab = { 4e c3 [2] 3a db [2] 7d d9 [2] 3a c8 [2] 74 c4 [2] 78 ce [2] 6f c5 [2] 74 8b [2] 49 }

  condition:
    any of them
}