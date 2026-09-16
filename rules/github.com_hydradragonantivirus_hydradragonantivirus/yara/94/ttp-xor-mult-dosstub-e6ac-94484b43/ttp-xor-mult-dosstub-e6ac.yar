rule TTP_XOR_MULT_DOSStub_e6ac {
  strings:
    $key_e6ac = { b2 c4 [2] c6 dc [2] 81 de [2] c6 cf [2] 88 c3 [2] 84 c9 [2] 93 c2 [2] 88 8c [2] b5 }

  condition:
    any of them
}