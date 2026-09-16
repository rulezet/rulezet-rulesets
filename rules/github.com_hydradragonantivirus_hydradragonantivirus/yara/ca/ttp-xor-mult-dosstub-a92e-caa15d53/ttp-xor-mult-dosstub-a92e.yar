rule TTP_XOR_MULT_DOSStub_a92e {
  strings:
    $key_a92e = { fd 46 [2] 89 5e [2] ce 5c [2] 89 4d [2] c7 41 [2] cb 4b [2] dc 40 [2] c7 0e [2] fa }

  condition:
    any of them
}