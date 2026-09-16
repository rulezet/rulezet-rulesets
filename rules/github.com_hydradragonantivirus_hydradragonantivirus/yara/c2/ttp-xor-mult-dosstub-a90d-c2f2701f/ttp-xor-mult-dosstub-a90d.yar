rule TTP_XOR_MULT_DOSStub_a90d {
  strings:
    $key_a90d = { fd 65 [2] 89 7d [2] ce 7f [2] 89 6e [2] c7 62 [2] cb 68 [2] dc 63 [2] c7 2d [2] fa }

  condition:
    any of them
}