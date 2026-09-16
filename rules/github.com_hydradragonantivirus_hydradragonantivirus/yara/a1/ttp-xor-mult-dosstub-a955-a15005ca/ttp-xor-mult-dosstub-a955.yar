rule TTP_XOR_MULT_DOSStub_a955 {
  strings:
    $key_a955 = { fd 3d [2] 89 25 [2] ce 27 [2] 89 36 [2] c7 3a [2] cb 30 [2] dc 3b [2] c7 75 [2] fa }

  condition:
    any of them
}