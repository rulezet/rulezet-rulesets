rule TTP_XOR_MULT_DOSStub_a93d {
  strings:
    $key_a93d = { fd 55 [2] 89 4d [2] ce 4f [2] 89 5e [2] c7 52 [2] cb 58 [2] dc 53 [2] c7 1d [2] fa }

  condition:
    any of them
}