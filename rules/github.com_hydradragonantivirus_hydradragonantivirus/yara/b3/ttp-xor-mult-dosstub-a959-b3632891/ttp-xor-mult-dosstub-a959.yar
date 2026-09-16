rule TTP_XOR_MULT_DOSStub_a959 {
  strings:
    $key_a959 = { fd 31 [2] 89 29 [2] ce 2b [2] 89 3a [2] c7 36 [2] cb 3c [2] dc 37 [2] c7 79 [2] fa }

  condition:
    any of them
}