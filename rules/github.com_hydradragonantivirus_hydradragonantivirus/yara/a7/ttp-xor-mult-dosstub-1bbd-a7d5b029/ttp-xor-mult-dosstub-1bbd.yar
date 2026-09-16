rule TTP_XOR_MULT_DOSStub_1bbd {
  strings:
    $key_1bbd = { 4f d5 [2] 3b cd [2] 7c cf [2] 3b de [2] 75 d2 [2] 79 d8 [2] 6e d3 [2] 75 9d [2] 48 }

  condition:
    any of them
}