rule TTP_XOR_MULT_DOSStub_aeaa {
  strings:
    $key_aeaa = { fa c2 [2] 8e da [2] c9 d8 [2] 8e c9 [2] c0 c5 [2] cc cf [2] db c4 [2] c0 8a [2] fd }

  condition:
    any of them
}