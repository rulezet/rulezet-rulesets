rule TTP_XOR_MULT_DOSStub_b3ac {
  strings:
    $key_b3ac = { e7 c4 [2] 93 dc [2] d4 de [2] 93 cf [2] dd c3 [2] d1 c9 [2] c6 c2 [2] dd 8c [2] e0 }

  condition:
    any of them
}