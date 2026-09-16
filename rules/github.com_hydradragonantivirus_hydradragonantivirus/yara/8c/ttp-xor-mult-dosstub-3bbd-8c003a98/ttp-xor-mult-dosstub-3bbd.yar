rule TTP_XOR_MULT_DOSStub_3bbd {
  strings:
    $key_3bbd = { 6f d5 [2] 1b cd [2] 5c cf [2] 1b de [2] 55 d2 [2] 59 d8 [2] 4e d3 [2] 55 9d [2] 68 }

  condition:
    any of them
}