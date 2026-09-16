rule TTP_XOR_MULT_DOSStub_a915 {
  strings:
    $key_a915 = { fd 7d [2] 89 65 [2] ce 67 [2] 89 76 [2] c7 7a [2] cb 70 [2] dc 7b [2] c7 35 [2] fa }

  condition:
    any of them
}