rule TTP_XOR_MULT_DOSStub_3fbd {
  strings:
    $key_3fbd = { 6b d5 [2] 1f cd [2] 58 cf [2] 1f de [2] 51 d2 [2] 5d d8 [2] 4a d3 [2] 51 9d [2] 6c }

  condition:
    any of them
}