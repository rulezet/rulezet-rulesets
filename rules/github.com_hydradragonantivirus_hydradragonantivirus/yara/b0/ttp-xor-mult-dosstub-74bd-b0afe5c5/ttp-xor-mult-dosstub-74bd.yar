rule TTP_XOR_MULT_DOSStub_74bd {
  strings:
    $key_74bd = { 20 d5 [2] 54 cd [2] 13 cf [2] 54 de [2] 1a d2 [2] 16 d8 [2] 01 d3 [2] 1a 9d [2] 27 }

  condition:
    any of them
}