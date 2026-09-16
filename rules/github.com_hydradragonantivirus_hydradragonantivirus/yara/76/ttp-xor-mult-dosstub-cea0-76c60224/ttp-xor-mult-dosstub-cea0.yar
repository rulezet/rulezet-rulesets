rule TTP_XOR_MULT_DOSStub_cea0 {
  strings:
    $key_cea0 = { 9a c8 [2] ee d0 [2] a9 d2 [2] ee c3 [2] a0 cf [2] ac c5 [2] bb ce [2] a0 80 [2] 9d }

  condition:
    any of them
}