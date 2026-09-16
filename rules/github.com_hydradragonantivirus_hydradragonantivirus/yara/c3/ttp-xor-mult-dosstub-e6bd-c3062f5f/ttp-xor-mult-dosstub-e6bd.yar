rule TTP_XOR_MULT_DOSStub_e6bd {
  strings:
    $key_e6bd = { b2 d5 [2] c6 cd [2] 81 cf [2] c6 de [2] 88 d2 [2] 84 d8 [2] 93 d3 [2] 88 9d [2] b5 }

  condition:
    any of them
}