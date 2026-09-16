rule TTP_XOR_MULT_DOSStub_cac8 {
  strings:
    $key_cac8 = { 9e a0 [2] ea b8 [2] ad ba [2] ea ab [2] a4 a7 [2] a8 ad [2] bf a6 [2] a4 e8 [2] 99 }

  condition:
    any of them
}