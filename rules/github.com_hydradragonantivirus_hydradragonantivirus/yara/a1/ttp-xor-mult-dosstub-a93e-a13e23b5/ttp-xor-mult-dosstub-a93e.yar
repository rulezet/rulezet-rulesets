rule TTP_XOR_MULT_DOSStub_a93e {
  strings:
    $key_a93e = { fd 56 [2] 89 4e [2] ce 4c [2] 89 5d [2] c7 51 [2] cb 5b [2] dc 50 [2] c7 1e [2] fa }

  condition:
    any of them
}