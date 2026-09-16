rule TTP_XOR_MULT_DOSStub_cfc9 {
  strings:
    $key_cfc9 = { 9b a1 [2] ef b9 [2] a8 bb [2] ef aa [2] a1 a6 [2] ad ac [2] ba a7 [2] a1 e9 [2] 9c }

  condition:
    any of them
}