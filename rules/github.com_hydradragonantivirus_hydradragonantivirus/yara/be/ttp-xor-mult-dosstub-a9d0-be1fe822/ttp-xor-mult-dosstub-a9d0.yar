rule TTP_XOR_MULT_DOSStub_a9d0 {
  strings:
    $key_a9d0 = { fd b8 [2] 89 a0 [2] ce a2 [2] 89 b3 [2] c7 bf [2] cb b5 [2] dc be [2] c7 f0 [2] fa }

  condition:
    any of them
}