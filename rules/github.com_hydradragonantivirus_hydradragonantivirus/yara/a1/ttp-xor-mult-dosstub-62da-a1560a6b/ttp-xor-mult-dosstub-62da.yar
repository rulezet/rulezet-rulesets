rule TTP_XOR_MULT_DOSStub_62da {
  strings:
    $key_62da = { 36 b2 [2] 42 aa [2] 05 a8 [2] 42 b9 [2] 0c b5 [2] 00 bf [2] 17 b4 [2] 0c fa [2] 31 }

  condition:
    any of them
}