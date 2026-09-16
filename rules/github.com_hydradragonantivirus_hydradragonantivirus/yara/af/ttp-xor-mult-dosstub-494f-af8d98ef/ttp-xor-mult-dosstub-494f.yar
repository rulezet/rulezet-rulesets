rule TTP_XOR_MULT_DOSStub_494f {
  strings:
    $key_494f = { 1d 27 [2] 69 3f [2] 2e 3d [2] 69 2c [2] 27 20 [2] 2b 2a [2] 3c 21 [2] 27 6f [2] 1a }

  condition:
    any of them
}