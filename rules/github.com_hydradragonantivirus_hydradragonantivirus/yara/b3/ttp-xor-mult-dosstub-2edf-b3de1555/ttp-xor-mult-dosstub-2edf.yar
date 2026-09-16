rule TTP_XOR_MULT_DOSStub_2edf {
  strings:
    $key_2edf = { 7a b7 [2] 0e af [2] 49 ad [2] 0e bc [2] 40 b0 [2] 4c ba [2] 5b b1 [2] 40 ff [2] 7d }

  condition:
    any of them
}