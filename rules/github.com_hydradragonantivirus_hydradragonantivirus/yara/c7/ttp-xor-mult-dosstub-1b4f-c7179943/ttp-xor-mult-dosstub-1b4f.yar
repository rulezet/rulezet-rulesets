rule TTP_XOR_MULT_DOSStub_1b4f {
  strings:
    $key_1b4f = { 4f 27 [2] 3b 3f [2] 7c 3d [2] 3b 2c [2] 75 20 [2] 79 2a [2] 6e 21 [2] 75 6f [2] 48 }

  condition:
    any of them
}