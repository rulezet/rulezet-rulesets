rule TTP_XOR_MULT_DOSStub_52da {
  strings:
    $key_52da = { 06 b2 [2] 72 aa [2] 35 a8 [2] 72 b9 [2] 3c b5 [2] 30 bf [2] 27 b4 [2] 3c fa [2] 01 }

  condition:
    any of them
}