rule TTP_XOR_MULT_DOSStub_72da {
  strings:
    $key_72da = { 26 b2 [2] 52 aa [2] 15 a8 [2] 52 b9 [2] 1c b5 [2] 10 bf [2] 07 b4 [2] 1c fa [2] 21 }

  condition:
    any of them
}