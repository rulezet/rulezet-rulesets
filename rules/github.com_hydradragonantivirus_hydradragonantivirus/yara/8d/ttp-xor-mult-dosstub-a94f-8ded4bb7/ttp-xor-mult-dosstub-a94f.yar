rule TTP_XOR_MULT_DOSStub_a94f {
  strings:
    $key_a94f = { fd 27 [2] 89 3f [2] ce 3d [2] 89 2c [2] c7 20 [2] cb 2a [2] dc 21 [2] c7 6f [2] fa }

  condition:
    any of them
}