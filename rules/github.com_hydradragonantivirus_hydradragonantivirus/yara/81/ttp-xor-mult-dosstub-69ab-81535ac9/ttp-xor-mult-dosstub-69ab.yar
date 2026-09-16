rule TTP_XOR_MULT_DOSStub_69ab {
  strings:
    $key_69ab = { 3d c3 [2] 49 db [2] 0e d9 [2] 49 c8 [2] 07 c4 [2] 0b ce [2] 1c c5 [2] 07 8b [2] 3a }

  condition:
    any of them
}