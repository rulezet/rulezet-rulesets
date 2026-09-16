rule TTP_XOR_MULT_DOSStub_2eab {
  strings:
    $key_2eab = { 7a c3 [2] 0e db [2] 49 d9 [2] 0e c8 [2] 40 c4 [2] 4c ce [2] 5b c5 [2] 40 8b [2] 7d }

  condition:
    any of them
}