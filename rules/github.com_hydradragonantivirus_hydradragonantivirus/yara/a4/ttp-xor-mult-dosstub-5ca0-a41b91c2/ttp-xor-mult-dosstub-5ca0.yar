rule TTP_XOR_MULT_DOSStub_5ca0 {
  strings:
    $key_5ca0 = { 08 c8 [2] 7c d0 [2] 3b d2 [2] 7c c3 [2] 32 cf [2] 3e c5 [2] 29 ce [2] 32 80 [2] 0f }

  condition:
    any of them
}