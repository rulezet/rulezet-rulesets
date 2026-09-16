rule TTP_XOR_MULT_DOSStub_69dc {
  strings:
    $key_69dc = { 3d b4 [2] 49 ac [2] 0e ae [2] 49 bf [2] 07 b3 [2] 0b b9 [2] 1c b2 [2] 07 fc [2] 3a }

  condition:
    any of them
}