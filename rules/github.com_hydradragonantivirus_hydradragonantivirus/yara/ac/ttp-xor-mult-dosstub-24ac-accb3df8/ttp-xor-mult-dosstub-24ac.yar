rule TTP_XOR_MULT_DOSStub_24ac {
  strings:
    $key_24ac = { 70 c4 [2] 04 dc [2] 43 de [2] 04 cf [2] 4a c3 [2] 46 c9 [2] 51 c2 [2] 4a 8c [2] 77 }

  condition:
    any of them
}