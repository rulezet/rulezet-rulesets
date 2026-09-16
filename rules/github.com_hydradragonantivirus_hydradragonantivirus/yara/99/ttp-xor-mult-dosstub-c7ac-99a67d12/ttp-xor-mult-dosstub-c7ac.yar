rule TTP_XOR_MULT_DOSStub_c7ac {
  strings:
    $key_c7ac = { 93 c4 [2] e7 dc [2] a0 de [2] e7 cf [2] a9 c3 [2] a5 c9 [2] b2 c2 [2] a9 8c [2] 94 }

  condition:
    any of them
}