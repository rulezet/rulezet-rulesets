rule TTP_XOR_MULT_DOSStub_3796 {
  strings:
    $key_3796 = { 63 fe [2] 17 e6 [2] 50 e4 [2] 17 f5 [2] 59 f9 [2] 55 f3 [2] 42 f8 [2] 59 b6 [2] 64 }

  condition:
    any of them
}