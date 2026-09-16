rule TTP_XOR_MULT_DOSStub_68a6 {
  strings:
    $key_68a6 = { 3c ce [2] 48 d6 [2] 0f d4 [2] 48 c5 [2] 06 c9 [2] 0a c3 [2] 1d c8 [2] 06 86 [2] 3b }

  condition:
    any of them
}