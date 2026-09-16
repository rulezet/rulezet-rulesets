rule TTP_XOR_MULT_DOSStub_34dc {
  strings:
    $key_34dc = { 60 b4 [2] 14 ac [2] 53 ae [2] 14 bf [2] 5a b3 [2] 56 b9 [2] 41 b2 [2] 5a fc [2] 67 }

  condition:
    any of them
}