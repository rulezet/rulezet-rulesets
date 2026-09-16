rule TTP_XOR_MULT_DOSStub_a944 {
  strings:
    $key_a944 = { fd 2c [2] 89 34 [2] ce 36 [2] 89 27 [2] c7 2b [2] cb 21 [2] dc 2a [2] c7 64 [2] fa }

  condition:
    any of them
}