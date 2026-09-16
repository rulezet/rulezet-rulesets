rule TTP_XOR_MULT_DOSStub_f1ac {
  strings:
    $key_f1ac = { a5 c4 [2] d1 dc [2] 96 de [2] d1 cf [2] 9f c3 [2] 93 c9 [2] 84 c2 [2] 9f 8c [2] a2 }

  condition:
    any of them
}