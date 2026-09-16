rule TTP_XOR_MULT_DOSStub_20bd {
  strings:
    $key_20bd = { 74 d5 [2] 00 cd [2] 47 cf [2] 00 de [2] 4e d2 [2] 42 d8 [2] 55 d3 [2] 4e 9d [2] 73 }

  condition:
    any of them
}