rule TTP_XOR_MULT_DOSStub_7fbd {
  strings:
    $key_7fbd = { 2b d5 [2] 5f cd [2] 18 cf [2] 5f de [2] 11 d2 [2] 1d d8 [2] 0a d3 [2] 11 9d [2] 2c }

  condition:
    any of them
}