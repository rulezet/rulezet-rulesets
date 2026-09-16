rule TTP_XOR_MULT_DOSStub_1bda {
  strings:
    $key_1bda = { 4f b2 [2] 3b aa [2] 7c a8 [2] 3b b9 [2] 75 b5 [2] 79 bf [2] 6e b4 [2] 75 fa [2] 48 }

  condition:
    any of them
}