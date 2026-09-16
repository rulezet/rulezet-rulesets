rule TTP_XOR_MULT_DOSStub_a796 {
  strings:
    $key_a796 = { f3 fe [2] 87 e6 [2] c0 e4 [2] 87 f5 [2] c9 f9 [2] c5 f3 [2] d2 f8 [2] c9 b6 [2] f4 }

  condition:
    any of them
}