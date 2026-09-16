rule TTP_XOR_MULT_DOSStub_0ebd {
  strings:
    $key_0ebd = { 5a d5 [2] 2e cd [2] 69 cf [2] 2e de [2] 60 d2 [2] 6c d8 [2] 7b d3 [2] 60 9d [2] 5d }

  condition:
    any of them
}