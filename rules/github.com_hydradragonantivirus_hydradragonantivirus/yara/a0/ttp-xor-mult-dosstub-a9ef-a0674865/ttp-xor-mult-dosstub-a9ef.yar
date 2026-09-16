rule TTP_XOR_MULT_DOSStub_a9ef {
  strings:
    $key_a9ef = { fd 87 [2] 89 9f [2] ce 9d [2] 89 8c [2] c7 80 [2] cb 8a [2] dc 81 [2] c7 cf [2] fa }

  condition:
    any of them
}