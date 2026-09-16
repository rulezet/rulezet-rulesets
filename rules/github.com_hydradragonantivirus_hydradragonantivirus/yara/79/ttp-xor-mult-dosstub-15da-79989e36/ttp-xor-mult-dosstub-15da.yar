rule TTP_XOR_MULT_DOSStub_15da {
  strings:
    $key_15da = { 41 b2 [2] 35 aa [2] 72 a8 [2] 35 b9 [2] 7b b5 [2] 77 bf [2] 60 b4 [2] 7b fa [2] 46 }

  condition:
    any of them
}