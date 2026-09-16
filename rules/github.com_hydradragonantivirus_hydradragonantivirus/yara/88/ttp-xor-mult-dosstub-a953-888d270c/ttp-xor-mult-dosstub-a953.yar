rule TTP_XOR_MULT_DOSStub_a953 {
  strings:
    $key_a953 = { fd 3b [2] 89 23 [2] ce 21 [2] 89 30 [2] c7 3c [2] cb 36 [2] dc 3d [2] c7 73 [2] fa }

  condition:
    any of them
}