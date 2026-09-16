rule TTP_XOR_MULT_DOSStub_eeb5 {
  strings:
    $key_eeb5 = { ba dd [2] ce c5 [2] 89 c7 [2] ce d6 [2] 80 da [2] 8c d0 [2] 9b db [2] 80 95 [2] bd }

  condition:
    any of them
}