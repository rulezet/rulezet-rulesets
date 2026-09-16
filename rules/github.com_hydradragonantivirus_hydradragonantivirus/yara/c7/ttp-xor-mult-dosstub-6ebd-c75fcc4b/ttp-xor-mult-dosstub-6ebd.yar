rule TTP_XOR_MULT_DOSStub_6ebd {
  strings:
    $key_6ebd = { 3a d5 [2] 4e cd [2] 09 cf [2] 4e de [2] 00 d2 [2] 0c d8 [2] 1b d3 [2] 00 9d [2] 3d }

  condition:
    any of them
}