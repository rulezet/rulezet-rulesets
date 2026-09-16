rule TTP_XOR_MULT_DOSStub_7fda {
  strings:
    $key_7fda = { 2b b2 [2] 5f aa [2] 18 a8 [2] 5f b9 [2] 11 b5 [2] 1d bf [2] 0a b4 [2] 11 fa [2] 2c }

  condition:
    any of them
}