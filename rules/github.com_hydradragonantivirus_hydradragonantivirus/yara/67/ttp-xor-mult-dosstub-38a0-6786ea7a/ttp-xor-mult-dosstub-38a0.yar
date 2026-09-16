rule TTP_XOR_MULT_DOSStub_38a0 {
  strings:
    $key_38a0 = { 6c c8 [2] 18 d0 [2] 5f d2 [2] 18 c3 [2] 56 cf [2] 5a c5 [2] 4d ce [2] 56 80 [2] 6b }

  condition:
    any of them
}