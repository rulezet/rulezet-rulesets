rule TTP_XOR_MULT_DOSStub_25bd {
  strings:
    $key_25bd = { 71 d5 [2] 05 cd [2] 42 cf [2] 05 de [2] 4b d2 [2] 47 d8 [2] 50 d3 [2] 4b 9d [2] 76 }

  condition:
    any of them
}