rule TTP_XOR_MULT_DOSStub_a945 {
  strings:
    $key_a945 = { fd 2d [2] 89 35 [2] ce 37 [2] 89 26 [2] c7 2a [2] cb 20 [2] dc 2b [2] c7 65 [2] fa }

  condition:
    any of them
}