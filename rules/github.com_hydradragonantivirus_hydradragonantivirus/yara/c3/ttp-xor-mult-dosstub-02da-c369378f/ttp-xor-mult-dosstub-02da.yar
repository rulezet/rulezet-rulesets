rule TTP_XOR_MULT_DOSStub_02da {
  strings:
    $key_02da = { 56 b2 [2] 22 aa [2] 65 a8 [2] 22 b9 [2] 6c b5 [2] 60 bf [2] 77 b4 [2] 6c fa [2] 51 }

  condition:
    any of them
}