rule TTP_XOR_MULT_DOSStub_12bd {
  strings:
    $key_12bd = { 46 d5 [2] 32 cd [2] 75 cf [2] 32 de [2] 7c d2 [2] 70 d8 [2] 67 d3 [2] 7c 9d [2] 41 }

  condition:
    any of them
}