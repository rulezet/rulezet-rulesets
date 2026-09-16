rule TTP_XOR_MULT_DOSStub_74dc {
  strings:
    $key_74dc = { 20 b4 [2] 54 ac [2] 13 ae [2] 54 bf [2] 1a b3 [2] 16 b9 [2] 01 b2 [2] 1a fc [2] 27 }

  condition:
    any of them
}