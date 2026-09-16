rule TTP_XOR_MULT_DOSStub_a6ec {
  strings:
    $key_a6ec = { f2 84 [2] 86 9c [2] c1 9e [2] 86 8f [2] c8 83 [2] c4 89 [2] d3 82 [2] c8 cc [2] f5 }

  condition:
    any of them
}