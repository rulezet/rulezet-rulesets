rule TTP_XOR_MULT_DOSStub_e7bd {
  strings:
    $key_e7bd = { b3 d5 [2] c7 cd [2] 80 cf [2] c7 de [2] 89 d2 [2] 85 d8 [2] 92 d3 [2] 89 9d [2] b4 }

  condition:
    any of them
}