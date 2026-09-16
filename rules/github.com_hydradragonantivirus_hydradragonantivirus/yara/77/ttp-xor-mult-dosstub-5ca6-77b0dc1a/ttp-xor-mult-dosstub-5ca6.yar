rule TTP_XOR_MULT_DOSStub_5ca6 {
  strings:
    $key_5ca6 = { 08 ce [2] 7c d6 [2] 3b d4 [2] 7c c5 [2] 32 c9 [2] 3e c3 [2] 29 c8 [2] 32 86 [2] 0f }

  condition:
    any of them
}