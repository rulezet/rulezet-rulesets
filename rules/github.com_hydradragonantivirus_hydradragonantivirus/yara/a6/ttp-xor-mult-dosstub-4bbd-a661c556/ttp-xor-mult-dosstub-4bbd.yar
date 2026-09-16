rule TTP_XOR_MULT_DOSStub_4bbd {
  strings:
    $key_4bbd = { 1f d5 [2] 6b cd [2] 2c cf [2] 6b de [2] 25 d2 [2] 29 d8 [2] 3e d3 [2] 25 9d [2] 18 }

  condition:
    any of them
}