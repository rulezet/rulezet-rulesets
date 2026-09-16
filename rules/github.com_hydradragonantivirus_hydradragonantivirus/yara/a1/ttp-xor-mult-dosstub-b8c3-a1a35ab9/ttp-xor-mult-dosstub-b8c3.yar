rule TTP_XOR_MULT_DOSStub_b8c3 {
  strings:
    $key_b8c3 = { ec ab [2] 98 b3 [2] df b1 [2] 98 a0 [2] d6 ac [2] da a6 [2] cd ad [2] d6 e3 [2] eb }

  condition:
    any of them
}