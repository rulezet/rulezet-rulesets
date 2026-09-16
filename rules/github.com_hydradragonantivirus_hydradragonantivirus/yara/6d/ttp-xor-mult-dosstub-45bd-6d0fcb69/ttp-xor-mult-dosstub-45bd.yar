rule TTP_XOR_MULT_DOSStub_45bd {
  strings:
    $key_45bd = { 11 d5 [2] 65 cd [2] 22 cf [2] 65 de [2] 2b d2 [2] 27 d8 [2] 30 d3 [2] 2b 9d [2] 16 }

  condition:
    any of them
}