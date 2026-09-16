rule TTP_XOR_MULT_DOSStub_fec9 {
  strings:
    $key_fec9 = { aa a1 [2] de b9 [2] 99 bb [2] de aa [2] 90 a6 [2] 9c ac [2] 8b a7 [2] 90 e9 [2] ad }

  condition:
    any of them
}