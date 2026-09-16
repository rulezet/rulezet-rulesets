rule TTP_XOR_MULT_DOSStub_58dc {
  strings:
    $key_58dc = { 0c b4 [2] 78 ac [2] 3f ae [2] 78 bf [2] 36 b3 [2] 3a b9 [2] 2d b2 [2] 36 fc [2] 0b }

  condition:
    any of them
}