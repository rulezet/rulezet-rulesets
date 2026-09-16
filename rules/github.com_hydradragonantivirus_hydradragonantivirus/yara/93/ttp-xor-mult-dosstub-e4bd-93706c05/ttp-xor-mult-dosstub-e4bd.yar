rule TTP_XOR_MULT_DOSStub_e4bd {
  strings:
    $key_e4bd = { b0 d5 [2] c4 cd [2] 83 cf [2] c4 de [2] 8a d2 [2] 86 d8 [2] 91 d3 [2] 8a 9d [2] b7 }

  condition:
    any of them
}