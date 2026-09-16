rule TTP_XOR_MULT_DOSStub_afbd {
  strings:
    $key_afbd = { fb d5 [2] 8f cd [2] c8 cf [2] 8f de [2] c1 d2 [2] cd d8 [2] da d3 [2] c1 9d [2] fc }

  condition:
    any of them
}