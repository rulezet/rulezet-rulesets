rule TTP_XOR_MULT_DOSStub_cea9 {
  strings:
    $key_cea9 = { 9a c1 [2] ee d9 [2] a9 db [2] ee ca [2] a0 c6 [2] ac cc [2] bb c7 [2] a0 89 [2] 9d }

  condition:
    any of them
}