rule TTP_XOR_MULT_DOSStub_85bd {
  strings:
    $key_85bd = { d1 d5 [2] a5 cd [2] e2 cf [2] a5 de [2] eb d2 [2] e7 d8 [2] f0 d3 [2] eb 9d [2] d6 }

  condition:
    any of them
}