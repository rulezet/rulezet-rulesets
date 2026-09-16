rule TTP_XOR_MULT_DOSStub_aebd {
  strings:
    $key_aebd = { fa d5 [2] 8e cd [2] c9 cf [2] 8e de [2] c0 d2 [2] cc d8 [2] db d3 [2] c0 9d [2] fd }

  condition:
    any of them
}