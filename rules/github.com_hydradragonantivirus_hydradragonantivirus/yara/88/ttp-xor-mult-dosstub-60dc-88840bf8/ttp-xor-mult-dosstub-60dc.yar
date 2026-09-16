rule TTP_XOR_MULT_DOSStub_60dc {
  strings:
    $key_60dc = { 34 b4 [2] 40 ac [2] 07 ae [2] 40 bf [2] 0e b3 [2] 02 b9 [2] 15 b2 [2] 0e fc [2] 33 }

  condition:
    any of them
}