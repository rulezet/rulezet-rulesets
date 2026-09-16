rule TTP_XOR_MULT_DOSStub_a6fc {
  strings:
    $key_a6fc = { f2 94 [2] 86 8c [2] c1 8e [2] 86 9f [2] c8 93 [2] c4 99 [2] d3 92 [2] c8 dc [2] f5 }

  condition:
    any of them
}