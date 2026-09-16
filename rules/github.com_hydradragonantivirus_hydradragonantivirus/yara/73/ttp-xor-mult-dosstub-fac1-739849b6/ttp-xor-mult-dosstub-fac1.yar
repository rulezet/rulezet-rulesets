rule TTP_XOR_MULT_DOSStub_fac1 {
  strings:
    $key_fac1 = { ae a9 [2] da b1 [2] 9d b3 [2] da a2 [2] 94 ae [2] 98 a4 [2] 8f af [2] 94 e1 [2] a9 }

  condition:
    any of them
}