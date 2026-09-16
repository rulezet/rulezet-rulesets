rule TTP_XOR_MULT_DOSStub_75dc {
  strings:
    $key_75dc = { 21 b4 [2] 55 ac [2] 12 ae [2] 55 bf [2] 1b b3 [2] 17 b9 [2] 00 b2 [2] 1b fc [2] 26 }

  condition:
    any of them
}