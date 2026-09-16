rule TTP_XOR_MULT_DOSStub_abbd {
  strings:
    $key_abbd = { ff d5 [2] 8b cd [2] cc cf [2] 8b de [2] c5 d2 [2] c9 d8 [2] de d3 [2] c5 9d [2] f8 }

  condition:
    any of them
}