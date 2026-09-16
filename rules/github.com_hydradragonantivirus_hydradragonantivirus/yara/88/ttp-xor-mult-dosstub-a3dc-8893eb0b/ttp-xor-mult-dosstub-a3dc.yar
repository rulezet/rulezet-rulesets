rule TTP_XOR_MULT_DOSStub_a3dc {
  strings:
    $key_a3dc = { f7 b4 [2] 83 ac [2] c4 ae [2] 83 bf [2] cd b3 [2] c1 b9 [2] d6 b2 [2] cd fc [2] f0 }

  condition:
    any of them
}