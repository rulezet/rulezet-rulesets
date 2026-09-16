rule TTP_XOR_MULT_DOSStub_47dc {
  strings:
    $key_47dc = { 13 b4 [2] 67 ac [2] 20 ae [2] 67 bf [2] 29 b3 [2] 25 b9 [2] 32 b2 [2] 29 fc [2] 14 }

  condition:
    any of them
}