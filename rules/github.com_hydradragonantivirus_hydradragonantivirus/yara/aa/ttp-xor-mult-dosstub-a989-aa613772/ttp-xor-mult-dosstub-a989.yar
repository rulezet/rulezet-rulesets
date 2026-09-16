rule TTP_XOR_MULT_DOSStub_a989 {
  strings:
    $key_a989 = { fd e1 [2] 89 f9 [2] ce fb [2] 89 ea [2] c7 e6 [2] cb ec [2] dc e7 [2] c7 a9 [2] fa }

  condition:
    any of them
}