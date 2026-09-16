rule TTP_XOR_MULT_DOSStub_babd {
  strings:
    $key_babd = { ee d5 [2] 9a cd [2] dd cf [2] 9a de [2] d4 d2 [2] d8 d8 [2] cf d3 [2] d4 9d [2] e9 }

  condition:
    any of them
}