rule TTP_XOR_MULT_DOSStub_a985 {
  strings:
    $key_a985 = { fd ed [2] 89 f5 [2] ce f7 [2] 89 e6 [2] c7 ea [2] cb e0 [2] dc eb [2] c7 a5 [2] fa }

  condition:
    any of them
}