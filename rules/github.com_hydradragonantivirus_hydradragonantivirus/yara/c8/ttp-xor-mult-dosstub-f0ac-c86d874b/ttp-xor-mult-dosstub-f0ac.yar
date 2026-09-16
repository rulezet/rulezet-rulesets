rule TTP_XOR_MULT_DOSStub_f0ac {
  strings:
    $key_f0ac = { a4 c4 [2] d0 dc [2] 97 de [2] d0 cf [2] 9e c3 [2] 92 c9 [2] 85 c2 [2] 9e 8c [2] a3 }

  condition:
    any of them
}