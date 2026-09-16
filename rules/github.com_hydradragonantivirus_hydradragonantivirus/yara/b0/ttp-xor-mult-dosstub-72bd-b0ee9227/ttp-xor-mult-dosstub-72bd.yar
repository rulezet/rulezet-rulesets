rule TTP_XOR_MULT_DOSStub_72bd {
  strings:
    $key_72bd = { 26 d5 [2] 52 cd [2] 15 cf [2] 52 de [2] 1c d2 [2] 10 d8 [2] 07 d3 [2] 1c 9d [2] 21 }

  condition:
    any of them
}