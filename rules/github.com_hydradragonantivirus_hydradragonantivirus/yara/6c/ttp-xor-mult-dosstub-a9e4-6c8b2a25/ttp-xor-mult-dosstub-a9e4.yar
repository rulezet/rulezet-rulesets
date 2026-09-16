rule TTP_XOR_MULT_DOSStub_a9e4 {
  strings:
    $key_a9e4 = { fd 8c [2] 89 94 [2] ce 96 [2] 89 87 [2] c7 8b [2] cb 81 [2] dc 8a [2] c7 c4 [2] fa }

  condition:
    any of them
}