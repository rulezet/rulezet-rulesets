rule TTP_XOR_MULT_DOSStub_cea4 {
  strings:
    $key_cea4 = { 9a cc [2] ee d4 [2] a9 d6 [2] ee c7 [2] a0 cb [2] ac c1 [2] bb ca [2] a0 84 [2] 9d }

  condition:
    any of them
}