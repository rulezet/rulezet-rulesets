rule TTP_XOR_MULT_DOSStub_67bd {
  strings:
    $key_67bd = { 33 d5 [2] 47 cd [2] 00 cf [2] 47 de [2] 09 d2 [2] 05 d8 [2] 12 d3 [2] 09 9d [2] 34 }

  condition:
    any of them
}