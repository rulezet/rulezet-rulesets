rule TTP_XOR_MULT_DOSStub_a9f7 {
  strings:
    $key_a9f7 = { fd 9f [2] 89 87 [2] ce 85 [2] 89 94 [2] c7 98 [2] cb 92 [2] dc 99 [2] c7 d7 [2] fa }

  condition:
    any of them
}