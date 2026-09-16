rule TTP_XOR_MULT_DOSStub_0ada {
  strings:
    $key_0ada = { 5e b2 [2] 2a aa [2] 6d a8 [2] 2a b9 [2] 64 b5 [2] 68 bf [2] 7f b4 [2] 64 fa [2] 59 }

  condition:
    any of them
}