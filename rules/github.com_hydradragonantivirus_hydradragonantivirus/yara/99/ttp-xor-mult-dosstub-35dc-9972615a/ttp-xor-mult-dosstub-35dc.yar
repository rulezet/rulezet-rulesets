rule TTP_XOR_MULT_DOSStub_35dc {
  strings:
    $key_35dc = { 61 b4 [2] 15 ac [2] 52 ae [2] 15 bf [2] 5b b3 [2] 57 b9 [2] 40 b2 [2] 5b fc [2] 66 }

  condition:
    any of them
}