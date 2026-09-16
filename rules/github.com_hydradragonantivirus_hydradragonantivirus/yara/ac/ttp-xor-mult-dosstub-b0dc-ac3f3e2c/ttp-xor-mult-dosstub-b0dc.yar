rule TTP_XOR_MULT_DOSStub_b0dc {
  strings:
    $key_b0dc = { e4 b4 [2] 90 ac [2] d7 ae [2] 90 bf [2] de b3 [2] d2 b9 [2] c5 b2 [2] de fc [2] e3 }

  condition:
    any of them
}