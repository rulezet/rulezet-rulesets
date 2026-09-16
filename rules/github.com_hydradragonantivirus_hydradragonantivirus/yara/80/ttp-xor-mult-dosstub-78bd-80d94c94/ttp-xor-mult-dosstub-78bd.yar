rule TTP_XOR_MULT_DOSStub_78bd {
  strings:
    $key_78bd = { 2c d5 [2] 58 cd [2] 1f cf [2] 58 de [2] 16 d2 [2] 1a d8 [2] 0d d3 [2] 16 9d [2] 2b }

  condition:
    any of them
}