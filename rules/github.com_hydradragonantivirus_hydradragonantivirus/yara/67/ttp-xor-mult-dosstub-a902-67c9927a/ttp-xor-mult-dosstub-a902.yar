rule TTP_XOR_MULT_DOSStub_a902 {
  strings:
    $key_a902 = { fd 6a [2] 89 72 [2] ce 70 [2] 89 61 [2] c7 6d [2] cb 67 [2] dc 6c [2] c7 22 [2] fa }

  condition:
    any of them
}