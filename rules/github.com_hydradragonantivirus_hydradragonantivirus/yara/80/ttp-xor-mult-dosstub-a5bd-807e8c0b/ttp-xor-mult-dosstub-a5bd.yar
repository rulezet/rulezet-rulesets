rule TTP_XOR_MULT_DOSStub_a5bd {
  strings:
    $key_a5bd = { f1 d5 [2] 85 cd [2] c2 cf [2] 85 de [2] cb d2 [2] c7 d8 [2] d0 d3 [2] cb 9d [2] f6 }

  condition:
    any of them
}