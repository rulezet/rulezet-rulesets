rule TTP_XOR_MULT_DOSStub_5bbd {
  strings:
    $key_5bbd = { 0f d5 [2] 7b cd [2] 3c cf [2] 7b de [2] 35 d2 [2] 39 d8 [2] 2e d3 [2] 35 9d [2] 08 }

  condition:
    any of them
}