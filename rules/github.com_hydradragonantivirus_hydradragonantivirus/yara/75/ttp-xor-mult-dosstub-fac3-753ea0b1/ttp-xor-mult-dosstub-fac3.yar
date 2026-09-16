rule TTP_XOR_MULT_DOSStub_fac3 {
  strings:
    $key_fac3 = { ae ab [2] da b3 [2] 9d b1 [2] da a0 [2] 94 ac [2] 98 a6 [2] 8f ad [2] 94 e3 [2] a9 }

  condition:
    any of them
}