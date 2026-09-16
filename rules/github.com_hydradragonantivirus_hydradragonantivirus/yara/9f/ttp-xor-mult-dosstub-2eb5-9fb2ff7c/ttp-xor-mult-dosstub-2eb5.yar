rule TTP_XOR_MULT_DOSStub_2eb5 {
  strings:
    $key_2eb5 = { 7a dd [2] 0e c5 [2] 49 c7 [2] 0e d6 [2] 40 da [2] 4c d0 [2] 5b db [2] 40 95 [2] 7d }

  condition:
    any of them
}