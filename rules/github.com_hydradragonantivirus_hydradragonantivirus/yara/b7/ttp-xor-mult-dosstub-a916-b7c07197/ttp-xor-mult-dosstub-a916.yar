rule TTP_XOR_MULT_DOSStub_a916 {
  strings:
    $key_a916 = { fd 7e [2] 89 66 [2] ce 64 [2] 89 75 [2] c7 79 [2] cb 73 [2] dc 78 [2] c7 36 [2] fa }

  condition:
    any of them
}