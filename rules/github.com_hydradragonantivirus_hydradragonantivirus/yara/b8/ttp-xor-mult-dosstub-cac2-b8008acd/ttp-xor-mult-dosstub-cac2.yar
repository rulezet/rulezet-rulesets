rule TTP_XOR_MULT_DOSStub_cac2 {
  strings:
    $key_cac2 = { 9e aa [2] ea b2 [2] ad b0 [2] ea a1 [2] a4 ad [2] a8 a7 [2] bf ac [2] a4 e2 [2] 99 }

  condition:
    any of them
}