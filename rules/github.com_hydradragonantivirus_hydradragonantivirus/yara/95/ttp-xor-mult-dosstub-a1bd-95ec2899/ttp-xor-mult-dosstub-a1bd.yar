rule TTP_XOR_MULT_DOSStub_a1bd {
  strings:
    $key_a1bd = { f5 d5 [2] 81 cd [2] c6 cf [2] 81 de [2] cf d2 [2] c3 d8 [2] d4 d3 [2] cf 9d [2] f2 }

  condition:
    any of them
}