rule TTP_XOR_MULT_DOSStub_72dc {
  strings:
    $key_72dc = { 26 b4 [2] 52 ac [2] 15 ae [2] 52 bf [2] 1c b3 [2] 10 b9 [2] 07 b2 [2] 1c fc [2] 21 }

  condition:
    any of them
}