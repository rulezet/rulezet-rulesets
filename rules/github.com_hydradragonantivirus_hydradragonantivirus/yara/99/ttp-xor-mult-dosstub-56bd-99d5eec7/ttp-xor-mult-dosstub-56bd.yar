rule TTP_XOR_MULT_DOSStub_56bd {
  strings:
    $key_56bd = { 02 d5 [2] 76 cd [2] 31 cf [2] 76 de [2] 38 d2 [2] 34 d8 [2] 23 d3 [2] 38 9d [2] 05 }

  condition:
    any of them
}