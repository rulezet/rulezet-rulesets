rule TTP_XOR_MULT_DOSStub_b0ac {
  strings:
    $key_b0ac = { e4 c4 [2] 90 dc [2] d7 de [2] 90 cf [2] de c3 [2] d2 c9 [2] c5 c2 [2] de 8c [2] e3 }

  condition:
    any of them
}