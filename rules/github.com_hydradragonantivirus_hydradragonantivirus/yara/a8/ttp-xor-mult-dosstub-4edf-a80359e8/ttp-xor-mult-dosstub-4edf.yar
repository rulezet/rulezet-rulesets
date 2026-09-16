rule TTP_XOR_MULT_DOSStub_4edf {
  strings:
    $key_4edf = { 1a b7 [2] 6e af [2] 29 ad [2] 6e bc [2] 20 b0 [2] 2c ba [2] 3b b1 [2] 20 ff [2] 1d }

  condition:
    any of them
}