rule TTP_XOR_MULT_DOSStub_d1dc {
  strings:
    $key_d1dc = { 85 b4 [2] f1 ac [2] b6 ae [2] f1 bf [2] bf b3 [2] b3 b9 [2] a4 b2 [2] bf fc [2] 82 }

  condition:
    any of them
}