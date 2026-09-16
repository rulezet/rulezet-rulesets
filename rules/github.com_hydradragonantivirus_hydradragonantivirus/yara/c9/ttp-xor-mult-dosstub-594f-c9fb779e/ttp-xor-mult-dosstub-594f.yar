rule TTP_XOR_MULT_DOSStub_594f {
  strings:
    $key_594f = { 0d 27 [2] 79 3f [2] 3e 3d [2] 79 2c [2] 37 20 [2] 3b 2a [2] 2c 21 [2] 37 6f [2] 0a }

  condition:
    any of them
}