rule TTP_XOR_MULT_DOSStub_39bd {
  strings:
    $key_39bd = { 6d d5 [2] 19 cd [2] 5e cf [2] 19 de [2] 57 d2 [2] 5b d8 [2] 4c d3 [2] 57 9d [2] 6a }

  condition:
    any of them
}