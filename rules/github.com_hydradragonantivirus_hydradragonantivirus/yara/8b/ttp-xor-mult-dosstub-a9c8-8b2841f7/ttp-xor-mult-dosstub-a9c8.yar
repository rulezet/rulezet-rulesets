rule TTP_XOR_MULT_DOSStub_a9c8 {
  strings:
    $key_a9c8 = { fd a0 [2] 89 b8 [2] ce ba [2] 89 ab [2] c7 a7 [2] cb ad [2] dc a6 [2] c7 e8 [2] fa }

  condition:
    any of them
}