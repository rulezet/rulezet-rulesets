rule TTP_XOR_MULT_DOSStub_cfc4 {
  strings:
    $key_cfc4 = { 9b ac [2] ef b4 [2] a8 b6 [2] ef a7 [2] a1 ab [2] ad a1 [2] ba aa [2] a1 e4 [2] 9c }

  condition:
    any of them
}