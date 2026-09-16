rule TTP_XOR_MULT_DOSStub_a9c9 {
  strings:
    $key_a9c9 = { fd a1 [2] 89 b9 [2] ce bb [2] 89 aa [2] c7 a6 [2] cb ac [2] dc a7 [2] c7 e9 [2] fa }

  condition:
    any of them
}