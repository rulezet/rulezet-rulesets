rule TTP_XOR_MULT_DOSStub_fac0 {
  strings:
    $key_fac0 = { ae a8 [2] da b0 [2] 9d b2 [2] da a3 [2] 94 af [2] 98 a5 [2] 8f ae [2] 94 e0 [2] a9 }

  condition:
    any of them
}