rule TTP_XOR_MULT_DOSStub_b8bd {
  strings:
    $key_b8bd = { ec d5 [2] 98 cd [2] df cf [2] 98 de [2] d6 d2 [2] da d8 [2] cd d3 [2] d6 9d [2] eb }

  condition:
    any of them
}