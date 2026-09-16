rule TTP_XOR_MULT_DOSStub_1eb5 {
  strings:
    $key_1eb5 = { 4a dd [2] 3e c5 [2] 79 c7 [2] 3e d6 [2] 70 da [2] 7c d0 [2] 6b db [2] 70 95 [2] 4d }

  condition:
    any of them
}