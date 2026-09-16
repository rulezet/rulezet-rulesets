rule TTP_XOR_MULT_DOSStub_a95d {
  strings:
    $key_a95d = { fd 35 [2] 89 2d [2] ce 2f [2] 89 3e [2] c7 32 [2] cb 38 [2] dc 33 [2] c7 7d [2] fa }

  condition:
    any of them
}