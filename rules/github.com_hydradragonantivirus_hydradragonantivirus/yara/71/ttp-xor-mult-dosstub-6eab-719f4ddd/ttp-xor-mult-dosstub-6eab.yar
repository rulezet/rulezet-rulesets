rule TTP_XOR_MULT_DOSStub_6eab {
  strings:
    $key_6eab = { 3a c3 [2] 4e db [2] 09 d9 [2] 4e c8 [2] 00 c4 [2] 0c ce [2] 1b c5 [2] 00 8b [2] 3d }

  condition:
    any of them
}