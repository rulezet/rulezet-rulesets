rule TTP_XOR_MULT_DOSStub_d4dc {
  strings:
    $key_d4dc = { 80 b4 [2] f4 ac [2] b3 ae [2] f4 bf [2] ba b3 [2] b6 b9 [2] a1 b2 [2] ba fc [2] 87 }

  condition:
    any of them
}