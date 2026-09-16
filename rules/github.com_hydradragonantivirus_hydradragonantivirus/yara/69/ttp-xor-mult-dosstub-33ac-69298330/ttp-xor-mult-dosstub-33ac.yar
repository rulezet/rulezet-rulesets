rule TTP_XOR_MULT_DOSStub_33ac {
  strings:
    $key_33ac = { 67 c4 [2] 13 dc [2] 54 de [2] 13 cf [2] 5d c3 [2] 51 c9 [2] 46 c2 [2] 5d 8c [2] 60 }

  condition:
    any of them
}