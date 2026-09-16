rule TTP_XOR_MULT_DOSStub_40bd {
  strings:
    $key_40bd = { 14 d5 [2] 60 cd [2] 27 cf [2] 60 de [2] 2e d2 [2] 22 d8 [2] 35 d3 [2] 2e 9d [2] 13 }

  condition:
    any of them
}