rule TTP_XOR_MULT_DOSStub_cea2 {
  strings:
    $key_cea2 = { 9a ca [2] ee d2 [2] a9 d0 [2] ee c1 [2] a0 cd [2] ac c7 [2] bb cc [2] a0 82 [2] 9d }

  condition:
    any of them
}