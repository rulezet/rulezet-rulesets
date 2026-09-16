rule TTP_XOR_MULT_DOSStub_5796 {
  strings:
    $key_5796 = { 03 fe [2] 77 e6 [2] 30 e4 [2] 77 f5 [2] 39 f9 [2] 35 f3 [2] 22 f8 [2] 39 b6 [2] 04 }

  condition:
    any of them
}