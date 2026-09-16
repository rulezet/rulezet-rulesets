rule TTP_XOR_MULT_DOSStub_e1bd {
  strings:
    $key_e1bd = { b5 d5 [2] c1 cd [2] 86 cf [2] c1 de [2] 8f d2 [2] 83 d8 [2] 94 d3 [2] 8f 9d [2] b2 }

  condition:
    any of them
}