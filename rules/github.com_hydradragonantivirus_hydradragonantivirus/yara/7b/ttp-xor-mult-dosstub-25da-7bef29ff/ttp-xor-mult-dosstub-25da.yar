rule TTP_XOR_MULT_DOSStub_25da {
  strings:
    $key_25da = { 71 b2 [2] 05 aa [2] 42 a8 [2] 05 b9 [2] 4b b5 [2] 47 bf [2] 50 b4 [2] 4b fa [2] 76 }

  condition:
    any of them
}