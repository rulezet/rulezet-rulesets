rule TTP_XOR_MULT_DOSStub_07dc {
  strings:
    $key_07dc = { 53 b4 [2] 27 ac [2] 60 ae [2] 27 bf [2] 69 b3 [2] 65 b9 [2] 72 b2 [2] 69 fc [2] 54 }

  condition:
    any of them
}