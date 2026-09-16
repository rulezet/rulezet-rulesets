rule TTP_XOR_MULT_DOSStub_a942 {
  strings:
    $key_a942 = { fd 2a [2] 89 32 [2] ce 30 [2] 89 21 [2] c7 2d [2] cb 27 [2] dc 2c [2] c7 62 [2] fa }

  condition:
    any of them
}