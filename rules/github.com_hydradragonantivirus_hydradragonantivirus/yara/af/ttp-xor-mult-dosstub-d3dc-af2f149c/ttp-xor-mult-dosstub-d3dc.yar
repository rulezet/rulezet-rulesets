rule TTP_XOR_MULT_DOSStub_d3dc {
  strings:
    $key_d3dc = { 87 b4 [2] f3 ac [2] b4 ae [2] f3 bf [2] bd b3 [2] b1 b9 [2] a6 b2 [2] bd fc [2] 80 }

  condition:
    any of them
}