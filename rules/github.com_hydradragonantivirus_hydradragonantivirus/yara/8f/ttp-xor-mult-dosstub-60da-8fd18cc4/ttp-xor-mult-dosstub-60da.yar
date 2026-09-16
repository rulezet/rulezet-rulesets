rule TTP_XOR_MULT_DOSStub_60da {
  strings:
    $key_60da = { 34 b2 [2] 40 aa [2] 07 a8 [2] 40 b9 [2] 0e b5 [2] 02 bf [2] 15 b4 [2] 0e fa [2] 33 }

  condition:
    any of them
}