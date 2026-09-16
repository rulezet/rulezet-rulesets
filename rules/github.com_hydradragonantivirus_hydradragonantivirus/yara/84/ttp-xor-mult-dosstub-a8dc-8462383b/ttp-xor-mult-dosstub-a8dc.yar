rule TTP_XOR_MULT_DOSStub_a8dc {
  strings:
    $key_a8dc = { fc b4 [2] 88 ac [2] cf ae [2] 88 bf [2] c6 b3 [2] ca b9 [2] dd b2 [2] c6 fc [2] fb }

  condition:
    any of them
}