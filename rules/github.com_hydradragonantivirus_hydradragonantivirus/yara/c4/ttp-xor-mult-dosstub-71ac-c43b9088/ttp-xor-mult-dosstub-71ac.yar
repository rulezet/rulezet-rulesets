rule TTP_XOR_MULT_DOSStub_71ac {
  strings:
    $key_71ac = { 25 c4 [2] 51 dc [2] 16 de [2] 51 cf [2] 1f c3 [2] 13 c9 [2] 04 c2 [2] 1f 8c [2] 22 }

  condition:
    any of them
}