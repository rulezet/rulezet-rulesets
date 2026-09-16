rule TTP_XOR_MULT_DOSStub_b2c5 {
  strings:
    $key_b2c5 = { e6 ad [2] 92 b5 [2] d5 b7 [2] 92 a6 [2] dc aa [2] d0 a0 [2] c7 ab [2] dc e5 [2] e1 }

  condition:
    any of them
}