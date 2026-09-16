rule TTP_XOR_MULT_DOSStub_32da {
  strings:
    $key_32da = { 66 b2 [2] 12 aa [2] 55 a8 [2] 12 b9 [2] 5c b5 [2] 50 bf [2] 47 b4 [2] 5c fa [2] 61 }

  condition:
    any of them
}