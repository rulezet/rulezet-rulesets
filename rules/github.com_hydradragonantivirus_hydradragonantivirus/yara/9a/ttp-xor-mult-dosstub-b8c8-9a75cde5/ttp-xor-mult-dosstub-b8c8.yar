rule TTP_XOR_MULT_DOSStub_b8c8 {
  strings:
    $key_b8c8 = { ec a0 [2] 98 b8 [2] df ba [2] 98 ab [2] d6 a7 [2] da ad [2] cd a6 [2] d6 e8 [2] eb }

  condition:
    any of them
}