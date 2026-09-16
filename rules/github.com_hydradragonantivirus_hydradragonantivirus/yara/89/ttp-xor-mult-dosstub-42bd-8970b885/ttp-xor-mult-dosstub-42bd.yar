rule TTP_XOR_MULT_DOSStub_42bd {
  strings:
    $key_42bd = { 16 d5 [2] 62 cd [2] 25 cf [2] 62 de [2] 2c d2 [2] 20 d8 [2] 37 d3 [2] 2c 9d [2] 11 }

  condition:
    any of them
}