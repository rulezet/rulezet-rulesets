rule TTP_XOR_MULT_DOSStub_c0ac {
  strings:
    $key_c0ac = { 94 c4 [2] e0 dc [2] a7 de [2] e0 cf [2] ae c3 [2] a2 c9 [2] b5 c2 [2] ae 8c [2] 93 }

  condition:
    any of them
}