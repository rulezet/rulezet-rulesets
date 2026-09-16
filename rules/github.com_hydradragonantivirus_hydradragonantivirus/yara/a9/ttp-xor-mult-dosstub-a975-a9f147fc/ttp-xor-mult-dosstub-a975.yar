rule TTP_XOR_MULT_DOSStub_a975 {
  strings:
    $key_a975 = { fd 1d [2] 89 05 [2] ce 07 [2] 89 16 [2] c7 1a [2] cb 10 [2] dc 1b [2] c7 55 [2] fa }

  condition:
    any of them
}