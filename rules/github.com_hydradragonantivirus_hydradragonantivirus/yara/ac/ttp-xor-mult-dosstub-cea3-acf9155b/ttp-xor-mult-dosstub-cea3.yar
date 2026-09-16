rule TTP_XOR_MULT_DOSStub_cea3 {
  strings:
    $key_cea3 = { 9a cb [2] ee d3 [2] a9 d1 [2] ee c0 [2] a0 cc [2] ac c6 [2] bb cd [2] a0 83 [2] 9d }

  condition:
    any of them
}