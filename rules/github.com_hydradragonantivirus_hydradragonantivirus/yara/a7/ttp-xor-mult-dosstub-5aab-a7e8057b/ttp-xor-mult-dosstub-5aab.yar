rule TTP_XOR_MULT_DOSStub_5aab {
  strings:
    $key_5aab = { 0e c3 [2] 7a db [2] 3d d9 [2] 7a c8 [2] 34 c4 [2] 38 ce [2] 2f c5 [2] 34 8b [2] 09 }

  condition:
    any of them
}