rule TTP_XOR_MULT_DOSStub_7edf {
  strings:
    $key_7edf = { 2a b7 [2] 5e af [2] 19 ad [2] 5e bc [2] 10 b0 [2] 1c ba [2] 0b b1 [2] 10 ff [2] 2d }

  condition:
    any of them
}