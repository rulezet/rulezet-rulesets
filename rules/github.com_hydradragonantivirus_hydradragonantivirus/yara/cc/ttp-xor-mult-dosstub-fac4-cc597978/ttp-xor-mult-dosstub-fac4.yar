rule TTP_XOR_MULT_DOSStub_fac4 {
  strings:
    $key_fac4 = { ae ac [2] da b4 [2] 9d b6 [2] da a7 [2] 94 ab [2] 98 a1 [2] 8f aa [2] 94 e4 [2] a9 }

  condition:
    any of them
}