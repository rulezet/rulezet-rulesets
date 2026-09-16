rule TTP_XOR_MULT_DOSStub_46da {
  strings:
    $key_46da = { 12 b2 [2] 66 aa [2] 21 a8 [2] 66 b9 [2] 28 b5 [2] 24 bf [2] 33 b4 [2] 28 fa [2] 15 }

  condition:
    any of them
}