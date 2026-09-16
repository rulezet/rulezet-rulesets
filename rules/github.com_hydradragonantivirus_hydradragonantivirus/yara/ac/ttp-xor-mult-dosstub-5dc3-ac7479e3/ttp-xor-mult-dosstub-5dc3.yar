rule TTP_XOR_MULT_DOSStub_5dc3 {
  strings:
    $key_5dc3 = { 09 ab [2] 7d b3 [2] 3a b1 [2] 7d a0 [2] 33 ac [2] 3f a6 [2] 28 ad [2] 33 e3 [2] 0e }

  condition:
    any of them
}