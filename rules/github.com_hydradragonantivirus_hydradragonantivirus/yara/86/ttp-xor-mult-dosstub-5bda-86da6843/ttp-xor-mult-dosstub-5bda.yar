rule TTP_XOR_MULT_DOSStub_5bda {
  strings:
    $key_5bda = { 0f b2 [2] 7b aa [2] 3c a8 [2] 7b b9 [2] 35 b5 [2] 39 bf [2] 2e b4 [2] 35 fa [2] 08 }

  condition:
    any of them
}