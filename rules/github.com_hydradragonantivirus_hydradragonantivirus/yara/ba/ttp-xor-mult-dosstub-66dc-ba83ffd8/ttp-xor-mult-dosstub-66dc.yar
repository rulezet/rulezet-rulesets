rule TTP_XOR_MULT_DOSStub_66dc {
  strings:
    $key_66dc = { 32 b4 [2] 46 ac [2] 01 ae [2] 46 bf [2] 08 b3 [2] 04 b9 [2] 13 b2 [2] 08 fc [2] 35 }

  condition:
    any of them
}