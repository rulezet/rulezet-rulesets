rule TTP_XOR_MULT_DOSStub_7eab {
  strings:
    $key_7eab = { 2a c3 [2] 5e db [2] 19 d9 [2] 5e c8 [2] 10 c4 [2] 1c ce [2] 0b c5 [2] 10 8b [2] 2d }

  condition:
    any of them
}