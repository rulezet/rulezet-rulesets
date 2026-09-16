rule TTP_XOR_MULT_DOSStub_4c4f {
  strings:
    $key_4c4f = { 18 27 [2] 6c 3f [2] 2b 3d [2] 6c 2c [2] 22 20 [2] 2e 2a [2] 39 21 [2] 22 6f [2] 1f }

  condition:
    any of them
}