rule TTP_XOR_MULT_DOSStub_0fbd {
  strings:
    $key_0fbd = { 5b d5 [2] 2f cd [2] 68 cf [2] 2f de [2] 61 d2 [2] 6d d8 [2] 7a d3 [2] 61 9d [2] 5c }

  condition:
    any of them
}