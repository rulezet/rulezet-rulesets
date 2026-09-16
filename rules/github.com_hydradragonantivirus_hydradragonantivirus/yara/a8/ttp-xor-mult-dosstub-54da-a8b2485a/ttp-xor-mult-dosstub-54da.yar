rule TTP_XOR_MULT_DOSStub_54da {
  strings:
    $key_54da = { 00 b2 [2] 74 aa [2] 33 a8 [2] 74 b9 [2] 3a b5 [2] 36 bf [2] 21 b4 [2] 3a fa [2] 07 }

  condition:
    any of them
}