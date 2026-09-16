rule TTP_XOR_MULT_DOSStub_b8c5 {
  strings:
    $key_b8c5 = { ec ad [2] 98 b5 [2] df b7 [2] 98 a6 [2] d6 aa [2] da a0 [2] cd ab [2] d6 e5 [2] eb }

  condition:
    any of them
}