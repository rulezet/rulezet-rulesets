rule TTP_XOR_MULT_DOSStub_5fda {
  strings:
    $key_5fda = { 0b b2 [2] 7f aa [2] 38 a8 [2] 7f b9 [2] 31 b5 [2] 3d bf [2] 2a b4 [2] 31 fa [2] 0c }

  condition:
    any of them
}