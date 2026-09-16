rule TTP_XOR_MULT_DOSStub_17dc {
  strings:
    $key_17dc = { 43 b4 [2] 37 ac [2] 70 ae [2] 37 bf [2] 79 b3 [2] 75 b9 [2] 62 b2 [2] 79 fc [2] 44 }

  condition:
    any of them
}