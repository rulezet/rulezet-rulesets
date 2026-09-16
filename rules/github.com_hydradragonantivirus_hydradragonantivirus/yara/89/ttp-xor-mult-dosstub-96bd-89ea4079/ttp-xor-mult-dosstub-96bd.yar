rule TTP_XOR_MULT_DOSStub_96bd {
  strings:
    $key_96bd = { c2 d5 [2] b6 cd [2] f1 cf [2] b6 de [2] f8 d2 [2] f4 d8 [2] e3 d3 [2] f8 9d [2] c5 }

  condition:
    any of them
}