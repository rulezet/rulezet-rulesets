rule TTP_XOR_MULT_DOSStub_a9f5 {
  strings:
    $key_a9f5 = { fd 9d [2] 89 85 [2] ce 87 [2] 89 96 [2] c7 9a [2] cb 90 [2] dc 9b [2] c7 d5 [2] fa }

  condition:
    any of them
}