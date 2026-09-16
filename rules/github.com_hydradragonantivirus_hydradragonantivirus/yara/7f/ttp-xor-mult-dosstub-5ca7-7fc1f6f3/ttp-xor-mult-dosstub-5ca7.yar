rule TTP_XOR_MULT_DOSStub_5ca7 {
  strings:
    $key_5ca7 = { 08 cf [2] 7c d7 [2] 3b d5 [2] 7c c4 [2] 32 c8 [2] 3e c2 [2] 29 c9 [2] 32 87 [2] 0f }

  condition:
    any of them
}