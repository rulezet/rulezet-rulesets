rule TTP_XOR_MULT_DOSStub_a4dc {
  strings:
    $key_a4dc = { f0 b4 [2] 84 ac [2] c3 ae [2] 84 bf [2] ca b3 [2] c6 b9 [2] d1 b2 [2] ca fc [2] f7 }

  condition:
    any of them
}