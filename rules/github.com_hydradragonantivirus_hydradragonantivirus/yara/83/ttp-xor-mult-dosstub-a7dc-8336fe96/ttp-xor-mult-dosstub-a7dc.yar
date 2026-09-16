rule TTP_XOR_MULT_DOSStub_a7dc {
  strings:
    $key_a7dc = { f3 b4 [2] 87 ac [2] c0 ae [2] 87 bf [2] c9 b3 [2] c5 b9 [2] d2 b2 [2] c9 fc [2] f4 }

  condition:
    any of them
}