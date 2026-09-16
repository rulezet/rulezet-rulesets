rule TTP_XOR_MULT_DOSStub_5eca {
  strings:
    $key_5eca = { 0a a2 [2] 7e ba [2] 39 b8 [2] 7e a9 [2] 30 a5 [2] 3c af [2] 2b a4 [2] 30 ea [2] 0d }

  condition:
    any of them
}