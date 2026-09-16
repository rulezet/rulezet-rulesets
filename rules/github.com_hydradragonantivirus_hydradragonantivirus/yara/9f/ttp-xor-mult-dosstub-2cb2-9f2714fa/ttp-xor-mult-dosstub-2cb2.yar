rule TTP_XOR_MULT_DOSStub_2cb2 {
  strings:
    $key_2cb2 = { 78 da [2] 0c c2 [2] 4b c0 [2] 0c d1 [2] 42 dd [2] 4e d7 [2] 59 dc [2] 42 92 [2] 7f }

  condition:
    any of them
}