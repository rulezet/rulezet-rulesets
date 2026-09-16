rule TTP_XOR_MULT_DOSStub_a90e {
  strings:
    $key_a90e = { fd 66 [2] 89 7e [2] ce 7c [2] 89 6d [2] c7 61 [2] cb 6b [2] dc 60 [2] c7 2e [2] fa }

  condition:
    any of them
}