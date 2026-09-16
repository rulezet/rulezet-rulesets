rule TTP_XOR_MULT_DOSStub_0bbd {
  strings:
    $key_0bbd = { 5f d5 [2] 2b cd [2] 6c cf [2] 2b de [2] 65 d2 [2] 69 d8 [2] 7e d3 [2] 65 9d [2] 58 }

  condition:
    any of them
}