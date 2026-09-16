rule TTP_XOR_MULT_DOSStub_1adf {
  strings:
    $key_1adf = { 4e b7 [2] 3a af [2] 7d ad [2] 3a bc [2] 74 b0 [2] 78 ba [2] 6f b1 [2] 74 ff [2] 49 }

  condition:
    any of them
}