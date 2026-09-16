rule TTP_XOR_MULT_DOSStub_05dc {
  strings:
    $key_05dc = { 51 b4 [2] 25 ac [2] 62 ae [2] 25 bf [2] 6b b3 [2] 67 b9 [2] 70 b2 [2] 6b fc [2] 56 }

  condition:
    any of them
}