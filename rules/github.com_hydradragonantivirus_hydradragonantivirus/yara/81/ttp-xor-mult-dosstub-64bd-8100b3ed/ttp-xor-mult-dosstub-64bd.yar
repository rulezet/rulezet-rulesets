rule TTP_XOR_MULT_DOSStub_64bd {
  strings:
    $key_64bd = { 30 d5 [2] 44 cd [2] 03 cf [2] 44 de [2] 0a d2 [2] 06 d8 [2] 11 d3 [2] 0a 9d [2] 37 }

  condition:
    any of them
}