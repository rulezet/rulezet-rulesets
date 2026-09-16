rule TTP_XOR_MULT_DOSStub_6eb3 {
  strings:
    $key_6eb3 = { 3a db [2] 4e c3 [2] 09 c1 [2] 4e d0 [2] 00 dc [2] 0c d6 [2] 1b dd [2] 00 93 [2] 3d }

  condition:
    any of them
}