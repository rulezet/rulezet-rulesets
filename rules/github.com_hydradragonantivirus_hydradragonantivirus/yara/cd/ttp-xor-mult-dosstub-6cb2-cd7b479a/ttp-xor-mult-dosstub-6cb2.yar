rule TTP_XOR_MULT_DOSStub_6cb2 {
  strings:
    $key_6cb2 = { 38 da [2] 4c c2 [2] 0b c0 [2] 4c d1 [2] 02 dd [2] 0e d7 [2] 19 dc [2] 02 92 [2] 3f }

  condition:
    any of them
}