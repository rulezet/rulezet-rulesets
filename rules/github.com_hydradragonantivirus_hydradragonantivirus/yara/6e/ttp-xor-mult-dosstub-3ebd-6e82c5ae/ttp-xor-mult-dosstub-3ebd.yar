rule TTP_XOR_MULT_DOSStub_3ebd {
  strings:
    $key_3ebd = { 6a d5 [2] 1e cd [2] 59 cf [2] 1e de [2] 50 d2 [2] 5c d8 [2] 4b d3 [2] 50 9d [2] 6d }

  condition:
    any of them
}