rule TTP_XOR_MULT_DOSStub_a965 {
  strings:
    $key_a965 = { fd 0d [2] 89 15 [2] ce 17 [2] 89 06 [2] c7 0a [2] cb 00 [2] dc 0b [2] c7 45 [2] fa }

  condition:
    any of them
}