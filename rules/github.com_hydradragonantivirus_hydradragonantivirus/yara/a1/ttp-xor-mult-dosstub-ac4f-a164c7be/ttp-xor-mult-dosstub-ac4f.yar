rule TTP_XOR_MULT_DOSStub_ac4f {
  strings:
    $key_ac4f = { f8 27 [2] 8c 3f [2] cb 3d [2] 8c 2c [2] c2 20 [2] ce 2a [2] d9 21 [2] c2 6f [2] ff }

  condition:
    any of them
}