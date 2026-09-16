rule TTP_XOR_MULT_DOSStub_a4bd {
  strings:
    $key_a4bd = { f0 d5 [2] 84 cd [2] c3 cf [2] 84 de [2] ca d2 [2] c6 d8 [2] d1 d3 [2] ca 9d [2] f7 }

  condition:
    any of them
}