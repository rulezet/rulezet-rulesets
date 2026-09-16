rule TTP_XOR_MULT_DOSStub_66da {
  strings:
    $key_66da = { 32 b2 [2] 46 aa [2] 01 a8 [2] 46 b9 [2] 08 b5 [2] 04 bf [2] 13 b4 [2] 08 fa [2] 35 }

  condition:
    any of them
}