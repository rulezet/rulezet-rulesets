rule TTP_XOR_MULT_DOSStub_6fda {
  strings:
    $key_6fda = { 3b b2 [2] 4f aa [2] 08 a8 [2] 4f b9 [2] 01 b5 [2] 0d bf [2] 1a b4 [2] 01 fa [2] 3c }

  condition:
    any of them
}