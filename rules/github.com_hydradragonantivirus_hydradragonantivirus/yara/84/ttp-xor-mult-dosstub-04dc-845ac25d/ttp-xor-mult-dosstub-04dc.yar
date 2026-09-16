rule TTP_XOR_MULT_DOSStub_04dc {
  strings:
    $key_04dc = { 50 b4 [2] 24 ac [2] 63 ae [2] 24 bf [2] 6a b3 [2] 66 b9 [2] 71 b2 [2] 6a fc [2] 57 }

  condition:
    any of them
}