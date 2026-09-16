rule TTP_XOR_MULT_DOSStub_28a6 {
  strings:
    $key_28a6 = { 7c ce [2] 08 d6 [2] 4f d4 [2] 08 c5 [2] 46 c9 [2] 4a c3 [2] 5d c8 [2] 46 86 [2] 7b }

  condition:
    any of them
}