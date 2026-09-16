rule TTP_XOR_MULT_DOSStub_b5ac {
  strings:
    $key_b5ac = { e1 c4 [2] 95 dc [2] d2 de [2] 95 cf [2] db c3 [2] d7 c9 [2] c0 c2 [2] db 8c [2] e6 }

  condition:
    any of them
}