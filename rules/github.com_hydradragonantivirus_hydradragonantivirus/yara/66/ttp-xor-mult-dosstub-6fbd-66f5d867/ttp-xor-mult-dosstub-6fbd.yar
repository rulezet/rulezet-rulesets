rule TTP_XOR_MULT_DOSStub_6fbd {
  strings:
    $key_6fbd = { 3b d5 [2] 4f cd [2] 08 cf [2] 4f de [2] 01 d2 [2] 0d d8 [2] 1a d3 [2] 01 9d [2] 3c }

  condition:
    any of them
}