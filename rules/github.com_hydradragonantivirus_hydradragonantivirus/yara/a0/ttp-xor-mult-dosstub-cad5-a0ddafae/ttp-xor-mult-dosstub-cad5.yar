rule TTP_XOR_MULT_DOSStub_cad5 {
  strings:
    $key_cad5 = { 9e bd [2] ea a5 [2] ad a7 [2] ea b6 [2] a4 ba [2] a8 b0 [2] bf bb [2] a4 f5 [2] 99 }

  condition:
    any of them
}