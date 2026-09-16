rule TTP_XOR_MULT_DOSStub_90bd {
  strings:
    $key_90bd = { c4 d5 [2] b0 cd [2] f7 cf [2] b0 de [2] fe d2 [2] f2 d8 [2] e5 d3 [2] fe 9d [2] c3 }

  condition:
    any of them
}