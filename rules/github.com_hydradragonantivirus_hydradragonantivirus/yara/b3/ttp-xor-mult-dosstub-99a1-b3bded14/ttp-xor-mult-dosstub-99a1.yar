rule TTP_XOR_MULT_DOSStub_99a1 {
  strings:
    $key_99a1 = { cd c9 [2] b9 d1 [2] fe d3 [2] b9 c2 [2] f7 ce [2] fb c4 [2] ec cf [2] f7 81 [2] ca }

  condition:
    any of them
}