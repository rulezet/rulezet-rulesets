rule TTP_XOR_MULT_DOSStub_d0dc {
  strings:
    $key_d0dc = { 84 b4 [2] f0 ac [2] b7 ae [2] f0 bf [2] be b3 [2] b2 b9 [2] a5 b2 [2] be fc [2] 83 }

  condition:
    any of them
}