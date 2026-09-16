rule TTP_XOR_MULT_DOSStub_2ebd {
  strings:
    $key_2ebd = { 7a d5 [2] 0e cd [2] 49 cf [2] 0e de [2] 40 d2 [2] 4c d8 [2] 5b d3 [2] 40 9d [2] 7d }

  condition:
    any of them
}