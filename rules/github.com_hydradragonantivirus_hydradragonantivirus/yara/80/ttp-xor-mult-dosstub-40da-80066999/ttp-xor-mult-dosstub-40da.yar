rule TTP_XOR_MULT_DOSStub_40da {
  strings:
    $key_40da = { 14 b2 [2] 60 aa [2] 27 a8 [2] 60 b9 [2] 2e b5 [2] 22 bf [2] 35 b4 [2] 2e fa [2] 13 }

  condition:
    any of them
}