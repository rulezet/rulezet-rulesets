rule TTP_XOR_MULT_DOSStub_63da {
  strings:
    $key_63da = { 37 b2 [2] 43 aa [2] 04 a8 [2] 43 b9 [2] 0d b5 [2] 01 bf [2] 16 b4 [2] 0d fa [2] 30 }

  condition:
    any of them
}