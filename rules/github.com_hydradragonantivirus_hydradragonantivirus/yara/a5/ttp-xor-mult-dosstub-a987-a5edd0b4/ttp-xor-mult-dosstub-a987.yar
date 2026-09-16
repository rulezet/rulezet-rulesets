rule TTP_XOR_MULT_DOSStub_a987 {
  strings:
    $key_a987 = { fd ef [2] 89 f7 [2] ce f5 [2] 89 e4 [2] c7 e8 [2] cb e2 [2] dc e9 [2] c7 a7 [2] fa }

  condition:
    any of them
}