rule TTP_XOR_MULT_DOSStub_a2bd {
  strings:
    $key_a2bd = { f6 d5 [2] 82 cd [2] c5 cf [2] 82 de [2] cc d2 [2] c0 d8 [2] d7 d3 [2] cc 9d [2] f1 }

  condition:
    any of them
}