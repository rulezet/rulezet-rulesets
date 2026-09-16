rule TTP_XOR_MULT_DOSStub_5cb3 {
  strings:
    $key_5cb3 = { 08 db [2] 7c c3 [2] 3b c1 [2] 7c d0 [2] 32 dc [2] 3e d6 [2] 29 dd [2] 32 93 [2] 0f }

  condition:
    any of them
}