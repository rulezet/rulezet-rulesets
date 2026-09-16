rule TTP_XOR_MULT_DOSStub_3aab {
  strings:
    $key_3aab = { 6e c3 [2] 1a db [2] 5d d9 [2] 1a c8 [2] 54 c4 [2] 58 ce [2] 4f c5 [2] 54 8b [2] 69 }

  condition:
    any of them
}