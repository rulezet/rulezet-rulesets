rule TTP_XOR_MULT_DOSStub_38a6 {
  strings:
    $key_38a6 = { 6c ce [2] 18 d6 [2] 5f d4 [2] 18 c5 [2] 56 c9 [2] 5a c3 [2] 4d c8 [2] 56 86 [2] 6b }

  condition:
    any of them
}