rule TTP_XOR_MULT_DOSStub_52bd {
  strings:
    $key_52bd = { 06 d5 [2] 72 cd [2] 35 cf [2] 72 de [2] 3c d2 [2] 30 d8 [2] 27 d3 [2] 3c 9d [2] 01 }

  condition:
    any of them
}