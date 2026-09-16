rule TTP_XOR_MULT_DOSStub_55bd {
  strings:
    $key_55bd = { 01 d5 [2] 75 cd [2] 32 cf [2] 75 de [2] 3b d2 [2] 37 d8 [2] 20 d3 [2] 3b 9d [2] 06 }

  condition:
    any of them
}