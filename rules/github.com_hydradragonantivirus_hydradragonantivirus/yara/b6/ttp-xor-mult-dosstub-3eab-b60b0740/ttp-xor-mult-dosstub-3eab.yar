rule TTP_XOR_MULT_DOSStub_3eab {
  strings:
    $key_3eab = { 6a c3 [2] 1e db [2] 59 d9 [2] 1e c8 [2] 50 c4 [2] 5c ce [2] 4b c5 [2] 50 8b [2] 6d }

  condition:
    any of them
}