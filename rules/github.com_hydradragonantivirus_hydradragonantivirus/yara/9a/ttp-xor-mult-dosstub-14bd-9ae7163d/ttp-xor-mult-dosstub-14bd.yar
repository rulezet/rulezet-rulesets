rule TTP_XOR_MULT_DOSStub_14bd {
  strings:
    $key_14bd = { 40 d5 [2] 34 cd [2] 73 cf [2] 34 de [2] 7a d2 [2] 76 d8 [2] 61 d3 [2] 7a 9d [2] 47 }

  condition:
    any of them
}