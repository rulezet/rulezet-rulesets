rule TTP_XOR_MULT_DOSStub_f8dc {
  strings:
    $key_f8dc = { ac b4 [2] d8 ac [2] 9f ae [2] d8 bf [2] 96 b3 [2] 9a b9 [2] 8d b2 [2] 96 fc [2] ab }

  condition:
    any of them
}