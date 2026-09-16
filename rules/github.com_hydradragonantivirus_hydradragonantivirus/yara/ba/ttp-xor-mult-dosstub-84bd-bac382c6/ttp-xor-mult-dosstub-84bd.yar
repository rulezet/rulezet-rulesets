rule TTP_XOR_MULT_DOSStub_84bd {
  strings:
    $key_84bd = { d0 d5 [2] a4 cd [2] e3 cf [2] a4 de [2] ea d2 [2] e6 d8 [2] f1 d3 [2] ea 9d [2] d7 }

  condition:
    any of them
}