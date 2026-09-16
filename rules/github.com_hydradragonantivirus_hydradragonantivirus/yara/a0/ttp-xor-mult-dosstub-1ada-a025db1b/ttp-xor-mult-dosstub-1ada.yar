rule TTP_XOR_MULT_DOSStub_1ada {
  strings:
    $key_1ada = { 4e b2 [2] 3a aa [2] 7d a8 [2] 3a b9 [2] 74 b5 [2] 78 bf [2] 6f b4 [2] 74 fa [2] 49 }

  condition:
    any of them
}