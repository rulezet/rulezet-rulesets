rule TTP_XOR_MULT_DOSStub_33dc {
  strings:
    $key_33dc = { 67 b4 [2] 13 ac [2] 54 ae [2] 13 bf [2] 5d b3 [2] 51 b9 [2] 46 b2 [2] 5d fc [2] 60 }

  condition:
    any of them
}