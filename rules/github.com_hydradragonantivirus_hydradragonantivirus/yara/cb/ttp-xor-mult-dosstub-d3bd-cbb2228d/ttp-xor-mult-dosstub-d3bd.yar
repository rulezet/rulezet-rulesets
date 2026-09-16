rule TTP_XOR_MULT_DOSStub_d3bd {
  strings:
    $key_d3bd = { 87 d5 [2] f3 cd [2] b4 cf [2] f3 de [2] bd d2 [2] b1 d8 [2] a6 d3 [2] bd 9d [2] 80 }

  condition:
    any of them
}