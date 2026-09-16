rule TTP_XOR_MULT_DOSStub_7eb5 {
  strings:
    $key_7eb5 = { 2a dd [2] 5e c5 [2] 19 c7 [2] 5e d6 [2] 10 da [2] 1c d0 [2] 0b db [2] 10 95 [2] 2d }

  condition:
    any of them
}