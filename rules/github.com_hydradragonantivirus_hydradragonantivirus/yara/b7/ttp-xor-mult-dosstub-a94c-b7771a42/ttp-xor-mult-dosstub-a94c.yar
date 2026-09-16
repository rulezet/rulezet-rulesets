rule TTP_XOR_MULT_DOSStub_a94c {
  strings:
    $key_a94c = { fd 24 [2] 89 3c [2] ce 3e [2] 89 2f [2] c7 23 [2] cb 29 [2] dc 22 [2] c7 6c [2] fa }

  condition:
    any of them
}