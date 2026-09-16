rule TTP_XOR_MULT_DOSStub_a7bd {
  strings:
    $key_a7bd = { f3 d5 [2] 87 cd [2] c0 cf [2] 87 de [2] c9 d2 [2] c5 d8 [2] d2 d3 [2] c9 9d [2] f4 }

  condition:
    any of them
}