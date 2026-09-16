rule TTP_XOR_MULT_DOSStub_a95f {
  strings:
    $key_a95f = { fd 37 [2] 89 2f [2] ce 2d [2] 89 3c [2] c7 30 [2] cb 3a [2] dc 31 [2] c7 7f [2] fa }

  condition:
    any of them
}