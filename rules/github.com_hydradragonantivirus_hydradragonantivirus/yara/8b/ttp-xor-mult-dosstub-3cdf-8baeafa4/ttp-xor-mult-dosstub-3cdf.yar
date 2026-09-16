rule TTP_XOR_MULT_DOSStub_3cdf {
  strings:
    $key_3cdf = { 68 b7 [2] 1c af [2] 5b ad [2] 1c bc [2] 52 b0 [2] 5e ba [2] 49 b1 [2] 52 ff [2] 6f }

  condition:
    any of them
}