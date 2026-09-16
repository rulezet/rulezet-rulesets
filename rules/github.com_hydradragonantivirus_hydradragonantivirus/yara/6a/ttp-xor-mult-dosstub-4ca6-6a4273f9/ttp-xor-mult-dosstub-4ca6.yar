rule TTP_XOR_MULT_DOSStub_4ca6 {
  strings:
    $key_4ca6 = { 18 ce [2] 6c d6 [2] 2b d4 [2] 6c c5 [2] 22 c9 [2] 2e c3 [2] 39 c8 [2] 22 86 [2] 1f }

  condition:
    any of them
}