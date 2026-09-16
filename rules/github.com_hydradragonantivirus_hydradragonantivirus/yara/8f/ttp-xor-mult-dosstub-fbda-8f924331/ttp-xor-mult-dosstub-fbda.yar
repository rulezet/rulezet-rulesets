rule TTP_XOR_MULT_DOSStub_fbda {
  strings:
    $key_fbda = { af b2 [2] db aa [2] 9c a8 [2] db b9 [2] 95 b5 [2] 99 bf [2] 8e b4 [2] 95 fa [2] a8 }

  condition:
    any of them
}