rule TTP_XOR_MULT_DOSStub_86bf {
  strings:
    $key_86bf = { d2 d7 [2] a6 cf [2] e1 cd [2] a6 dc [2] e8 d0 [2] e4 da [2] f3 d1 [2] e8 9f [2] d5 }

  condition:
    any of them
}