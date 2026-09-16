rule TTP_XOR_MULT_DOSStub_7bdf {
  strings:
    $key_7bdf = { 2f b7 [2] 5b af [2] 1c ad [2] 5b bc [2] 15 b0 [2] 19 ba [2] 0e b1 [2] 15 ff [2] 28 }

  condition:
    any of them
}