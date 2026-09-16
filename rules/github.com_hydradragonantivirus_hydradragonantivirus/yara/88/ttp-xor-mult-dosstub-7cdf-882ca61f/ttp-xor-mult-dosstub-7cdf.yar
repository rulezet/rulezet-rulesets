rule TTP_XOR_MULT_DOSStub_7cdf {
  strings:
    $key_7cdf = { 28 b7 [2] 5c af [2] 1b ad [2] 5c bc [2] 12 b0 [2] 1e ba [2] 09 b1 [2] 12 ff [2] 2f }

  condition:
    any of them
}