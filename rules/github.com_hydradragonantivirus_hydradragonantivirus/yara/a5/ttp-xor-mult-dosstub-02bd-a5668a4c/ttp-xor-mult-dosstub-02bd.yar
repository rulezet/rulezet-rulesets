rule TTP_XOR_MULT_DOSStub_02bd {
  strings:
    $key_02bd = { 56 d5 [2] 22 cd [2] 65 cf [2] 22 de [2] 6c d2 [2] 60 d8 [2] 77 d3 [2] 6c 9d [2] 51 }

  condition:
    any of them
}