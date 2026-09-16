rule TTP_XOR_MULT_DOSStub_a999 {
  strings:
    $key_a999 = { fd f1 [2] 89 e9 [2] ce eb [2] 89 fa [2] c7 f6 [2] cb fc [2] dc f7 [2] c7 b9 [2] fa }

  condition:
    any of them
}