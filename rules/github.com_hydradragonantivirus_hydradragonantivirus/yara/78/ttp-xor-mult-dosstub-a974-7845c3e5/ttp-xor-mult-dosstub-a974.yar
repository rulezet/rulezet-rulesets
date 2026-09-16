rule TTP_XOR_MULT_DOSStub_a974 {
  strings:
    $key_a974 = { fd 1c [2] 89 04 [2] ce 06 [2] 89 17 [2] c7 1b [2] cb 11 [2] dc 1a [2] c7 54 [2] fa }

  condition:
    any of them
}