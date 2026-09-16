rule TTP_XOR_MULT_DOSStub_a2dc {
  strings:
    $key_a2dc = { f6 b4 [2] 82 ac [2] c5 ae [2] 82 bf [2] cc b3 [2] c0 b9 [2] d7 b2 [2] cc fc [2] f1 }

  condition:
    any of them
}