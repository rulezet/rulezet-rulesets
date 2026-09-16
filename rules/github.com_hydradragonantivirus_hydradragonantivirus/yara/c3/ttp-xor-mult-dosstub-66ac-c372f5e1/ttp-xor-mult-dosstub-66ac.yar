rule TTP_XOR_MULT_DOSStub_66ac {
  strings:
    $key_66ac = { 32 c4 [2] 46 dc [2] 01 de [2] 46 cf [2] 08 c3 [2] 04 c9 [2] 13 c2 [2] 08 8c [2] 35 }

  condition:
    any of them
}