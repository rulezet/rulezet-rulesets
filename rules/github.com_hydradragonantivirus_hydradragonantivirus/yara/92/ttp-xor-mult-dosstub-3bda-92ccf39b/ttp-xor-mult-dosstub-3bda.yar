rule TTP_XOR_MULT_DOSStub_3bda {
  strings:
    $key_3bda = { 6f b2 [2] 1b aa [2] 5c a8 [2] 1b b9 [2] 55 b5 [2] 59 bf [2] 4e b4 [2] 55 fa [2] 68 }

  condition:
    any of them
}