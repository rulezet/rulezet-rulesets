rule TTP_XOR_MULT_DOSStub_67dc {
  strings:
    $key_67dc = { 33 b4 [2] 47 ac [2] 00 ae [2] 47 bf [2] 09 b3 [2] 05 b9 [2] 12 b2 [2] 09 fc [2] 34 }

  condition:
    any of them
}