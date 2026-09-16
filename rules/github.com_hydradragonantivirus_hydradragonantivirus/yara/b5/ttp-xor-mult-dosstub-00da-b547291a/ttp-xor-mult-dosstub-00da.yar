rule TTP_XOR_MULT_DOSStub_00da {
  strings:
    $key_00da = { 54 b2 [2] 20 aa [2] 67 a8 [2] 20 b9 [2] 6e b5 [2] 62 bf [2] 75 b4 [2] 6e fa [2] 53 }

  condition:
    any of them
}