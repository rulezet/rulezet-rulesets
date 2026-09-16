rule TTP_XOR_MULT_DOSStub_a96e {
  strings:
    $key_a96e = { fd 06 [2] 89 1e [2] ce 1c [2] 89 0d [2] c7 01 [2] cb 0b [2] dc 00 [2] c7 4e [2] fa }

  condition:
    any of them
}