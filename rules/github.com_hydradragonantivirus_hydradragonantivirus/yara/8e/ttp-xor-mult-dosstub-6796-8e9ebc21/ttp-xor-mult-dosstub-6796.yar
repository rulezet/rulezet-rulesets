rule TTP_XOR_MULT_DOSStub_6796 {
  strings:
    $key_6796 = { 33 fe [2] 47 e6 [2] 00 e4 [2] 47 f5 [2] 09 f9 [2] 05 f3 [2] 12 f8 [2] 09 b6 [2] 34 }

  condition:
    any of them
}