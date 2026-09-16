rule TTP_XOR_MULT_DOSStub_68dc {
  strings:
    $key_68dc = { 3c b4 [2] 48 ac [2] 0f ae [2] 48 bf [2] 06 b3 [2] 0a b9 [2] 1d b2 [2] 06 fc [2] 3b }

  condition:
    any of them
}