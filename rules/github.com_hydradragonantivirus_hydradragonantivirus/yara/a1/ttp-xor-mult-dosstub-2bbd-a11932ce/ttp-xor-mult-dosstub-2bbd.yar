rule TTP_XOR_MULT_DOSStub_2bbd {
  strings:
    $key_2bbd = { 7f d5 [2] 0b cd [2] 4c cf [2] 0b de [2] 45 d2 [2] 49 d8 [2] 5e d3 [2] 45 9d [2] 78 }

  condition:
    any of them
}