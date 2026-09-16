rule TTP_XOR_MULT_DOSStub_08bd {
  strings:
    $key_08bd = { 5c d5 [2] 28 cd [2] 6f cf [2] 28 de [2] 66 d2 [2] 6a d8 [2] 7d d3 [2] 66 9d [2] 5b }

  condition:
    any of them
}