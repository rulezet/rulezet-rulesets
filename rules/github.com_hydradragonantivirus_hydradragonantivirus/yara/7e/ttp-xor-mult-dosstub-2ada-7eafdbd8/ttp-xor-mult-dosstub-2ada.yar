rule TTP_XOR_MULT_DOSStub_2ada {
  strings:
    $key_2ada = { 7e b2 [2] 0a aa [2] 4d a8 [2] 0a b9 [2] 44 b5 [2] 48 bf [2] 5f b4 [2] 44 fa [2] 79 }

  condition:
    any of them
}