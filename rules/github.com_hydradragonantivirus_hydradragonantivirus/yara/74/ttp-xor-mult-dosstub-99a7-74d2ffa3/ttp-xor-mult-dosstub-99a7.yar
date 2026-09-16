rule TTP_XOR_MULT_DOSStub_99a7 {
  strings:
    $key_99a7 = { cd cf [2] b9 d7 [2] fe d5 [2] b9 c4 [2] f7 c8 [2] fb c2 [2] ec c9 [2] f7 87 [2] ca }

  condition:
    any of them
}