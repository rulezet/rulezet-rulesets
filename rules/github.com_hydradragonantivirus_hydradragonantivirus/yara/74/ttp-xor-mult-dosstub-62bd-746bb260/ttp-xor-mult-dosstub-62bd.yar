rule TTP_XOR_MULT_DOSStub_62bd {
  strings:
    $key_62bd = { 36 d5 [2] 42 cd [2] 05 cf [2] 42 de [2] 0c d2 [2] 00 d8 [2] 17 d3 [2] 0c 9d [2] 31 }

  condition:
    any of them
}