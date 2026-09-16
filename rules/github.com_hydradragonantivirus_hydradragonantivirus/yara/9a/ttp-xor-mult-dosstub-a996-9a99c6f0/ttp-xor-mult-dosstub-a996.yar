rule TTP_XOR_MULT_DOSStub_a996 {
  strings:
    $key_a996 = { fd fe [2] 89 e6 [2] ce e4 [2] 89 f5 [2] c7 f9 [2] cb f3 [2] dc f8 [2] c7 b6 [2] fa }

  condition:
    any of them
}