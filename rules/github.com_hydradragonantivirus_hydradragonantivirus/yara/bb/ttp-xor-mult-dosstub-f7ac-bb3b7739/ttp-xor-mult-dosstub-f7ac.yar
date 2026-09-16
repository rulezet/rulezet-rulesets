rule TTP_XOR_MULT_DOSStub_f7ac {
  strings:
    $key_f7ac = { a3 c4 [2] d7 dc [2] 90 de [2] d7 cf [2] 99 c3 [2] 95 c9 [2] 82 c2 [2] 99 8c [2] a4 }

  condition:
    any of them
}