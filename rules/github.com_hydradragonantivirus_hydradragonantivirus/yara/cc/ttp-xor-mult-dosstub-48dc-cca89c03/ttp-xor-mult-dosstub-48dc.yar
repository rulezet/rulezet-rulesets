rule TTP_XOR_MULT_DOSStub_48dc {
  strings:
    $key_48dc = { 1c b4 [2] 68 ac [2] 2f ae [2] 68 bf [2] 26 b3 [2] 2a b9 [2] 3d b2 [2] 26 fc [2] 1b }

  condition:
    any of them
}