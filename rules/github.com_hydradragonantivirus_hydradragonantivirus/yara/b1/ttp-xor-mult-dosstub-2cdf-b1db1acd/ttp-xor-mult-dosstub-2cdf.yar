rule TTP_XOR_MULT_DOSStub_2cdf {
  strings:
    $key_2cdf = { 78 b7 [2] 0c af [2] 4b ad [2] 0c bc [2] 42 b0 [2] 4e ba [2] 59 b1 [2] 42 ff [2] 7f }

  condition:
    any of them
}