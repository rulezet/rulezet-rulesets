rule TTP_XOR_MULT_DOSStub_6cb3 {
  strings:
    $key_6cb3 = { 38 db [2] 4c c3 [2] 0b c1 [2] 4c d0 [2] 02 dc [2] 0e d6 [2] 19 dd [2] 02 93 [2] 3f }

  condition:
    any of them
}