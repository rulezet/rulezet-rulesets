rule TTP_XOR_MULT_DOSStub_2eb2 {
  strings:
    $key_2eb2 = { 7a da [2] 0e c2 [2] 49 c0 [2] 0e d1 [2] 40 dd [2] 4c d7 [2] 5b dc [2] 40 92 [2] 7d }

  condition:
    any of them
}