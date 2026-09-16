rule TTP_XOR_MULT_DOSStub_cea1 {
  strings:
    $key_cea1 = { 9a c9 [2] ee d1 [2] a9 d3 [2] ee c2 [2] a0 ce [2] ac c4 [2] bb cf [2] a0 81 [2] 9d }

  condition:
    any of them
}