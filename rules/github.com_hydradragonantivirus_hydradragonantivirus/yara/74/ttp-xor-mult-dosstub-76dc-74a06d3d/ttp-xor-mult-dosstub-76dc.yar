rule TTP_XOR_MULT_DOSStub_76dc {
  strings:
    $key_76dc = { 22 b4 [2] 56 ac [2] 11 ae [2] 56 bf [2] 18 b3 [2] 14 b9 [2] 03 b2 [2] 18 fc [2] 25 }

  condition:
    any of them
}