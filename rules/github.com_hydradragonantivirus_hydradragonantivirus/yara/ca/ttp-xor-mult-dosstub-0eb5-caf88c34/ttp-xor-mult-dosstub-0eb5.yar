rule TTP_XOR_MULT_DOSStub_0eb5 {
  strings:
    $key_0eb5 = { 5a dd [2] 2e c5 [2] 69 c7 [2] 2e d6 [2] 60 da [2] 6c d0 [2] 7b db [2] 60 95 [2] 5d }

  condition:
    any of them
}