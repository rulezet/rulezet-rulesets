rule TTP_XOR_MULT_DOSStub_cac9 {
  strings:
    $key_cac9 = { 9e a1 [2] ea b9 [2] ad bb [2] ea aa [2] a4 a6 [2] a8 ac [2] bf a7 [2] a4 e9 [2] 99 }

  condition:
    any of them
}