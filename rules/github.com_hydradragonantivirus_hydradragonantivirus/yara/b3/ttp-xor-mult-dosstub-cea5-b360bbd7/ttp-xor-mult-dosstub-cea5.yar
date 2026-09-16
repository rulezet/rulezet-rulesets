rule TTP_XOR_MULT_DOSStub_cea5 {
  strings:
    $key_cea5 = { 9a cd [2] ee d5 [2] a9 d7 [2] ee c6 [2] a0 ca [2] ac c0 [2] bb cb [2] a0 85 [2] 9d }

  condition:
    any of them
}