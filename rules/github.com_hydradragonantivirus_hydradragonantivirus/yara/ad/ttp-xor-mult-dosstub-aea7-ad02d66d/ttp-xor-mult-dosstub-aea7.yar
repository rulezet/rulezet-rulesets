rule TTP_XOR_MULT_DOSStub_aea7 {
  strings:
    $key_aea7 = { fa cf [2] 8e d7 [2] c9 d5 [2] 8e c4 [2] c0 c8 [2] cc c2 [2] db c9 [2] c0 87 [2] fd }

  condition:
    any of them
}