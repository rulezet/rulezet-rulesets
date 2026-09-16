rule TTP_XOR_MULT_DOSStub_a9c7 {
  strings:
    $key_a9c7 = { fd af [2] 89 b7 [2] ce b5 [2] 89 a4 [2] c7 a8 [2] cb a2 [2] dc a9 [2] c7 e7 [2] fa }

  condition:
    any of them
}