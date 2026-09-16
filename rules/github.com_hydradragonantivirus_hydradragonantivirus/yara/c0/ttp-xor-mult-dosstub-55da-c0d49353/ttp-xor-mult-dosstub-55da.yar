rule TTP_XOR_MULT_DOSStub_55da {
  strings:
    $key_55da = { 01 b2 [2] 75 aa [2] 32 a8 [2] 75 b9 [2] 3b b5 [2] 37 bf [2] 20 b4 [2] 3b fa [2] 06 }

  condition:
    any of them
}