rule TTP_XOR_MULT_DOSStub_3dc3 {
  strings:
    $key_3dc3 = { 69 ab [2] 1d b3 [2] 5a b1 [2] 1d a0 [2] 53 ac [2] 5f a6 [2] 48 ad [2] 53 e3 [2] 6e }

  condition:
    any of them
}