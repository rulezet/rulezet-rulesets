rule TTP_XOR_MULT_DOSStub_a9fc {
  strings:
    $key_a9fc = { fd 94 [2] 89 8c [2] ce 8e [2] 89 9f [2] c7 93 [2] cb 99 [2] dc 92 [2] c7 dc [2] fa }

  condition:
    any of them
}