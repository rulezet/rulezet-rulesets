rule TTP_XOR_MULT_DOSStub_3cb4 {
  strings:
    $key_3cb4 = { 68 dc [2] 1c c4 [2] 5b c6 [2] 1c d7 [2] 52 db [2] 5e d1 [2] 49 da [2] 52 94 [2] 6f }

  condition:
    any of them
}