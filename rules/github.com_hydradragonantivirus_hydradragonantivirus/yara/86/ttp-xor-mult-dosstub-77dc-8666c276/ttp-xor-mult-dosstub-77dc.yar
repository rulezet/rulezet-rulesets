rule TTP_XOR_MULT_DOSStub_77dc {
  strings:
    $key_77dc = { 23 b4 [2] 57 ac [2] 10 ae [2] 57 bf [2] 19 b3 [2] 15 b9 [2] 02 b2 [2] 19 fc [2] 24 }

  condition:
    any of them
}