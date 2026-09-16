rule TTP_XOR_MULT_DOSStub_a6eb {
  strings:
    $key_a6eb = { f2 83 [2] 86 9b [2] c1 99 [2] 86 88 [2] c8 84 [2] c4 8e [2] d3 85 [2] c8 cb [2] f5 }

  condition:
    any of them
}