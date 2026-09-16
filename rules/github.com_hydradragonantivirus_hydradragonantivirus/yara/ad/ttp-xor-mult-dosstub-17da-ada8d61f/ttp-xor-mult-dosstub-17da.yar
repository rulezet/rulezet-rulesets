rule TTP_XOR_MULT_DOSStub_17da {
  strings:
    $key_17da = { 43 b2 [2] 37 aa [2] 70 a8 [2] 37 b9 [2] 79 b5 [2] 75 bf [2] 62 b4 [2] 79 fa [2] 44 }

  condition:
    any of them
}