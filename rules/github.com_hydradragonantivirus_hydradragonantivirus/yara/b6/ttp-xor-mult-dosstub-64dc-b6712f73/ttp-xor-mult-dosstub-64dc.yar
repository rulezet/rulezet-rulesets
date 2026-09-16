rule TTP_XOR_MULT_DOSStub_64dc {
  strings:
    $key_64dc = { 30 b4 [2] 44 ac [2] 03 ae [2] 44 bf [2] 0a b3 [2] 06 b9 [2] 11 b2 [2] 0a fc [2] 37 }

  condition:
    any of them
}