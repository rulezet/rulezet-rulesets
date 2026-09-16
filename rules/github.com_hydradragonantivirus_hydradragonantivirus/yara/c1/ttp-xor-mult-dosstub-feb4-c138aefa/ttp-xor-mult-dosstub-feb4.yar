rule TTP_XOR_MULT_DOSStub_feb4 {
  strings:
    $key_feb4 = { aa dc [2] de c4 [2] 99 c6 [2] de d7 [2] 90 db [2] 9c d1 [2] 8b da [2] 90 94 [2] ad }

  condition:
    any of them
}