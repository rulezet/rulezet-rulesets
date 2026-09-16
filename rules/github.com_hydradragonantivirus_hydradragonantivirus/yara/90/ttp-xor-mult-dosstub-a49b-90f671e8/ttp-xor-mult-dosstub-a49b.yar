rule TTP_XOR_MULT_DOSStub_a49b {
  strings:
    $key_a49b = { f0 f3 [2] 84 eb [2] c3 e9 [2] 84 f8 [2] ca f4 [2] c6 fe [2] d1 f5 [2] ca bb [2] f7 }

  condition:
    any of them
}