rule TTP_XOR_MULT_DOSStub_29a0 {
  strings:
    $key_29a0 = { 7d c8 [2] 09 d0 [2] 4e d2 [2] 09 c3 [2] 47 cf [2] 4b c5 [2] 5c ce [2] 47 80 [2] 7a }

  condition:
    any of them
}