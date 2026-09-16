rule TTP_XOR_MULT_DOSStub_a39b {
  strings:
    $key_a39b = { f7 f3 [2] 83 eb [2] c4 e9 [2] 83 f8 [2] cd f4 [2] c1 fe [2] d6 f5 [2] cd bb [2] f0 }

  condition:
    any of them
}