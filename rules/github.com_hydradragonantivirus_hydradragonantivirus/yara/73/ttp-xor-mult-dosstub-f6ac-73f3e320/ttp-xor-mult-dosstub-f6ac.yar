rule TTP_XOR_MULT_DOSStub_f6ac {
  strings:
    $key_f6ac = { a2 c4 [2] d6 dc [2] 91 de [2] d6 cf [2] 98 c3 [2] 94 c9 [2] 83 c2 [2] 98 8c [2] a5 }

  condition:
    any of them
}