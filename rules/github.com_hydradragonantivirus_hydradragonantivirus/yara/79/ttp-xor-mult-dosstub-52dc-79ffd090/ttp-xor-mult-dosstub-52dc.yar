rule TTP_XOR_MULT_DOSStub_52dc {
  strings:
    $key_52dc = { 06 b4 [2] 72 ac [2] 35 ae [2] 72 bf [2] 3c b3 [2] 30 b9 [2] 27 b2 [2] 3c fc [2] 01 }

  condition:
    any of them
}