rule TTP_XOR_MULT_DOSStub_bbbd {
  strings:
    $key_bbbd = { ef d5 [2] 9b cd [2] dc cf [2] 9b de [2] d5 d2 [2] d9 d8 [2] ce d3 [2] d5 9d [2] e8 }

  condition:
    any of them
}