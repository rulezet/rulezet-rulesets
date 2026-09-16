rule TTP_XOR_MULT_DOSStub_fac8 {
  strings:
    $key_fac8 = { ae a0 [2] da b8 [2] 9d ba [2] da ab [2] 94 a7 [2] 98 ad [2] 8f a6 [2] 94 e8 [2] a9 }

  condition:
    any of them
}