rule TTP_XOR_MULT_DOSStub_10bd {
  strings:
    $key_10bd = { 44 d5 [2] 30 cd [2] 77 cf [2] 30 de [2] 7e d2 [2] 72 d8 [2] 65 d3 [2] 7e 9d [2] 43 }

  condition:
    any of them
}