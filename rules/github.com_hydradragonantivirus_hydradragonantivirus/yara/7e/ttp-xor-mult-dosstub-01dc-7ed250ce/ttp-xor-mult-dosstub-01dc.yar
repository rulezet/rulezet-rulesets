rule TTP_XOR_MULT_DOSStub_01dc {
  strings:
    $key_01dc = { 55 b4 [2] 21 ac [2] 66 ae [2] 21 bf [2] 6f b3 [2] 63 b9 [2] 74 b2 [2] 6f fc [2] 52 }

  condition:
    any of them
}