rule TTP_XOR_MULT_DOSStub_58ab {
  strings:
    $key_58ab = { 0c c3 [2] 78 db [2] 3f d9 [2] 78 c8 [2] 36 c4 [2] 3a ce [2] 2d c5 [2] 36 8b [2] 0b }

  condition:
    any of them
}