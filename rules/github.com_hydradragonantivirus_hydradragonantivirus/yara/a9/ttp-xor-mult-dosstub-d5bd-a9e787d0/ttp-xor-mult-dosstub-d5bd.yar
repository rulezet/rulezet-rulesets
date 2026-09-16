rule TTP_XOR_MULT_DOSStub_d5bd {
  strings:
    $key_d5bd = { 81 d5 [2] f5 cd [2] b2 cf [2] f5 de [2] bb d2 [2] b7 d8 [2] a0 d3 [2] bb 9d [2] 86 }

  condition:
    any of them
}