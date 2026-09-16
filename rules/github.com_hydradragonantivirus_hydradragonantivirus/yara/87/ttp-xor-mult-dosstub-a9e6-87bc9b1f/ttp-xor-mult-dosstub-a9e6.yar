rule TTP_XOR_MULT_DOSStub_a9e6 {
  strings:
    $key_a9e6 = { fd 8e [2] 89 96 [2] ce 94 [2] 89 85 [2] c7 89 [2] cb 83 [2] dc 88 [2] c7 c6 [2] fa }

  condition:
    any of them
}