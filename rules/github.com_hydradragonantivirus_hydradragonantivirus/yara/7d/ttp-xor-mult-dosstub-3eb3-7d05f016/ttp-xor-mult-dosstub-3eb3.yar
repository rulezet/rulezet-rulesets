rule TTP_XOR_MULT_DOSStub_3eb3 {
  strings:
    $key_3eb3 = { 6a db [2] 1e c3 [2] 59 c1 [2] 1e d0 [2] 50 dc [2] 5c d6 [2] 4b dd [2] 50 93 [2] 6d }

  condition:
    any of them
}