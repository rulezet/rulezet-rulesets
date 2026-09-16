rule TTP_XOR_MULT_DOSStub_a905 {
  strings:
    $key_a905 = { fd 6d [2] 89 75 [2] ce 77 [2] 89 66 [2] c7 6a [2] cb 60 [2] dc 6b [2] c7 25 [2] fa }

  condition:
    any of them
}