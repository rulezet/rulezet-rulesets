rule TTP_XOR_MULT_DOSStub_2bda {
  strings:
    $key_2bda = { 7f b2 [2] 0b aa [2] 4c a8 [2] 0b b9 [2] 45 b5 [2] 49 bf [2] 5e b4 [2] 45 fa [2] 78 }

  condition:
    any of them
}