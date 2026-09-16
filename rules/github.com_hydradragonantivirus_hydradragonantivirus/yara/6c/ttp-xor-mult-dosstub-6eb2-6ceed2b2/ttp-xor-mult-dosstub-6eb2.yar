rule TTP_XOR_MULT_DOSStub_6eb2 {
  strings:
    $key_6eb2 = { 3a da [2] 4e c2 [2] 09 c0 [2] 4e d1 [2] 00 dd [2] 0c d7 [2] 1b dc [2] 00 92 [2] 3d }

  condition:
    any of them
}