rule TTP_XOR_MULT_DOSStub_794f {
  strings:
    $key_794f = { 2d 27 [2] 59 3f [2] 1e 3d [2] 59 2c [2] 17 20 [2] 1b 2a [2] 0c 21 [2] 17 6f [2] 2a }

  condition:
    any of them
}