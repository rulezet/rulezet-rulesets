rule TTP_XOR_MULT_DOSStub_68a0 {
  strings:
    $key_68a0 = { 3c c8 [2] 48 d0 [2] 0f d2 [2] 48 c3 [2] 06 cf [2] 0a c5 [2] 1d ce [2] 06 80 [2] 3b }

  condition:
    any of them
}