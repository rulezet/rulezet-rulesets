rule TTP_XOR_MULT_DOSStub_a918 {
  strings:
    $key_a918 = { fd 70 [2] 89 68 [2] ce 6a [2] 89 7b [2] c7 77 [2] cb 7d [2] dc 76 [2] c7 38 [2] fa }

  condition:
    any of them
}