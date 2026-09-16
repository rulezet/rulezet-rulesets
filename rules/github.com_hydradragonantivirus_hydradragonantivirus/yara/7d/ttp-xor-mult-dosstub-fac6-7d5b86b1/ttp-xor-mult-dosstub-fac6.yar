rule TTP_XOR_MULT_DOSStub_fac6 {
  strings:
    $key_fac6 = { ae ae [2] da b6 [2] 9d b4 [2] da a5 [2] 94 a9 [2] 98 a3 [2] 8f a8 [2] 94 e6 [2] a9 }

  condition:
    any of them
}