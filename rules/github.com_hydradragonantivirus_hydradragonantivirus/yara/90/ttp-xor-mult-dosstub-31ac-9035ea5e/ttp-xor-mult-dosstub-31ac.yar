rule TTP_XOR_MULT_DOSStub_31ac {
  strings:
    $key_31ac = { 65 c4 [2] 11 dc [2] 56 de [2] 11 cf [2] 5f c3 [2] 53 c9 [2] 44 c2 [2] 5f 8c [2] 62 }

  condition:
    any of them
}