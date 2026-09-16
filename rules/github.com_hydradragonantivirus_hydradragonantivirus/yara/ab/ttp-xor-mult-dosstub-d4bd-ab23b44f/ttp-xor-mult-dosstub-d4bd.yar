rule TTP_XOR_MULT_DOSStub_d4bd {
  strings:
    $key_d4bd = { 80 d5 [2] f4 cd [2] b3 cf [2] f4 de [2] ba d2 [2] b6 d8 [2] a1 d3 [2] ba 9d [2] 87 }

  condition:
    any of them
}