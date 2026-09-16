rule TTP_XOR_MULT_DOSStub_73da {
  strings:
    $key_73da = { 27 b2 [2] 53 aa [2] 14 a8 [2] 53 b9 [2] 1d b5 [2] 11 bf [2] 06 b4 [2] 1d fa [2] 20 }

  condition:
    any of them
}