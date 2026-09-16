rule TTP_XOR_MULT_DOSStub_a99a {
  strings:
    $key_a99a = { fd f2 [2] 89 ea [2] ce e8 [2] 89 f9 [2] c7 f5 [2] cb ff [2] dc f4 [2] c7 ba [2] fa }

  condition:
    any of them
}