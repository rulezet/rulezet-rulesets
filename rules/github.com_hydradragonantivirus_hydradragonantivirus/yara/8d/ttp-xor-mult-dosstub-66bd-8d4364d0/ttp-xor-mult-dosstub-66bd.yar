rule TTP_XOR_MULT_DOSStub_66bd {
  strings:
    $key_66bd = { 32 d5 [2] 46 cd [2] 01 cf [2] 46 de [2] 08 d2 [2] 04 d8 [2] 13 d3 [2] 08 9d [2] 35 }

  condition:
    any of them
}