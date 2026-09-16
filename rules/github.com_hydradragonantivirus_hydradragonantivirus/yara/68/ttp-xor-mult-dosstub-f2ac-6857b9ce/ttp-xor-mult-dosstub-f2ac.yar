rule TTP_XOR_MULT_DOSStub_f2ac {
  strings:
    $key_f2ac = { a6 c4 [2] d2 dc [2] 95 de [2] d2 cf [2] 9c c3 [2] 90 c9 [2] 87 c2 [2] 9c 8c [2] a1 }

  condition:
    any of them
}