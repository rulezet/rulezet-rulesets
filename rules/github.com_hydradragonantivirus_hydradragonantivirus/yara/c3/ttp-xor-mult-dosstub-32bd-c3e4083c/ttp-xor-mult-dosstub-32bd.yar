rule TTP_XOR_MULT_DOSStub_32bd {
  strings:
    $key_32bd = { 66 d5 [2] 12 cd [2] 55 cf [2] 12 de [2] 5c d2 [2] 50 d8 [2] 47 d3 [2] 5c 9d [2] 61 }

  condition:
    any of them
}