rule TTP_XOR_MULT_DOSStub_a6ae {
  strings:
    $key_a6ae = { f2 c6 [2] 86 de [2] c1 dc [2] 86 cd [2] c8 c1 [2] c4 cb [2] d3 c0 [2] c8 8e [2] f5 }

  condition:
    any of them
}