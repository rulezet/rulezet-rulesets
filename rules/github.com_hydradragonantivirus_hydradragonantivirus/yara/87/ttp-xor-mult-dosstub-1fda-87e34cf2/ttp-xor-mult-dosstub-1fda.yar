rule TTP_XOR_MULT_DOSStub_1fda {
  strings:
    $key_1fda = { 4b b2 [2] 3f aa [2] 78 a8 [2] 3f b9 [2] 71 b5 [2] 7d bf [2] 6a b4 [2] 71 fa [2] 4c }

  condition:
    any of them
}