rule TTP_XOR_MULT_DOSStub_5ebd {
  strings:
    $key_5ebd = { 0a d5 [2] 7e cd [2] 39 cf [2] 7e de [2] 30 d2 [2] 3c d8 [2] 2b d3 [2] 30 9d [2] 0d }

  condition:
    any of them
}