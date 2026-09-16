rule TTP_XOR_MULT_DOSStub_5eab {
  strings:
    $key_5eab = { 0a c3 [2] 7e db [2] 39 d9 [2] 7e c8 [2] 30 c4 [2] 3c ce [2] 2b c5 [2] 30 8b [2] 0d }

  condition:
    any of them
}